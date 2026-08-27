// ★ T-Pass SSO 消費端驗章（契約 v2）★
//
// 這個套件存在的唯一理由：驗章那四道檢查以前是「六個服務各一份手抄副本」。
// 抄漏 audience 不會有任何測試失敗、登入照樣成功——只有在別人拿其他服務的通行證
// 來打的時候才會發現。這種安靜的錯誤不能靠人類抄寫來防守。
//
// 安全四鐵則（在 verifyToken 裡，缺一不可；改動前先讀 tpass-auth/INTEGRATION.md）：
//   1. 鎖 algorithms: ["EdDSA"] —— 不鎖會有 alg confusion 偽造風險（公鑰被當對稱密鑰）。
//   2. 檢查 issuer —— 確認票是「這個 auth」簽的。
//   3. 檢查 audience === tpass:<本服務id> —— 票是簽給「我」的；別的服務的 token 必須驗不過。
//   4. 檢查 exp —— jose 預設會驗，別關掉。
//
// 驗章只能在 server 端做（cookie 是 HttpOnly，瀏覽器 JS 拿不到）。
import { createRemoteJWKSet, jwtVerify } from "jose";
/**
 * 安全預設：claim 缺 permissions、或沒有該 serviceId 的 key（舊票、或非 overview 服務
 * 對別的 serviceId 沒有資料）→ 一律視為「能讀、預設角色」。
 * 不因為缺資料就把既有使用者鎖在門外（fail-open 是這裡刻意的選擇：
 * 真正的門禁是「驗章通過」，permissions 只決定他在服務內能做多少事）。
 */
const DEFAULT_PERMISSION = { read: true, role: "default" };
function normalizeBase(url) {
    return url.replace(/\/+$/, "");
}
/**
 * 從標準環境變數組出設定。各服務的「自己的網址」env 名稱不同（FORM_SELF_URL、
 * PORTAL_SELF_URL…），所以那一顆的名字要傳進來。
 *
 * 缺值就直接 throw（fail closed）：與其讓服務帶著半套設定跑起來、在第一次登入時
 * 靜默鬼打牆，不如啟動就炸並列出缺哪幾顆。
 */
export function configFromEnv(selfUrlEnvName, env = process.env) {
    const REQUIRED = [
        "AUTH_JWKS_URL",
        "AUTH_AUTHORIZE_URL",
        "AUTH_LOGOUT_URL",
        "TPASS_SERVICE_ID",
        "JWT_ISSUER",
        selfUrlEnvName,
    ];
    const missing = REQUIRED.filter((k) => !env[k]);
    if (missing.length > 0) {
        throw new Error(`[tpass-auth-js] 缺少必填環境變數：${missing.join(", ")}（請檢查 .env.local）`);
    }
    return {
        jwksUrl: env.AUTH_JWKS_URL,
        issuer: env.JWT_ISSUER,
        serviceId: env.TPASS_SERVICE_ID,
        selfUrl: env[selfUrlEnvName],
        authorizeUrl: env.AUTH_AUTHORIZE_URL,
        authLogoutUrl: env.AUTH_LOGOUT_URL,
        deniedUrl: env.AUTH_DENIED_URL,
        cookieName: env.TPASS_COOKIE_NAME,
    };
}
/**
 * 建一個綁定本服務設定的驗章器。一個服務建一次（模組層級 const），
 * 這樣 JWKS 的記憶體快取才會共用。
 */
export function createTpassAuth(config) {
    const selfUrl = normalizeBase(config.selfUrl);
    const audience = `tpass:${config.serviceId}`;
    const cookieName = config.cookieName || "tpass_token";
    const authOrigin = new URL(config.authorizeUrl).origin;
    const deniedBase = config.deniedUrl || `${authOrigin}/denied`;
    // createRemoteJWKSet 內建記憶體快取 + 依 kid 選鑰 + 金鑰輪替時自動重抓（含冷卻）。
    // 首次驗章才會真的 fetch 一次 JWKS。
    const jwks = createRemoteJWKSet(new URL(config.jwksUrl));
    return {
        serviceId: config.serviceId,
        audience,
        cookieName,
        cookieSecure: selfUrl.startsWith("https://"),
        selfUrl,
        issuer: config.issuer,
        authOrigin,
        adminUrl: `${authOrigin}/admin`,
        logoutUrl: `${selfUrl}/api/auth/logout`,
        authLogoutUrl: config.authLogoutUrl,
        loginUrl(returnPath = "/") {
            const u = new URL(config.authorizeUrl);
            u.searchParams.set("service", config.serviceId);
            u.searchParams.set("redirect_uri", `${selfUrl}/api/auth/callback`);
            u.searchParams.set("next", returnPath);
            return u.toString();
        },
        deniedUrl(serviceId = config.serviceId) {
            const u = new URL(deniedBase);
            // reason 絕不放進 query string——auth 的 /denied 自己憑 session 在 server side 重查。
            u.searchParams.set("service", serviceId);
            return u.toString();
        },
        async verifyToken(token) {
            try {
                const { payload } = await jwtVerify(token, jwks, {
                    algorithms: ["EdDSA"], // 鐵則 1
                    issuer: config.issuer, // 鐵則 2
                    audience, // 鐵則 3
                    // 鐵則 4：exp 由 jose 預設驗，沒有任何一行關掉它。
                });
                return {
                    sub: payload.sub,
                    email: payload.email,
                    name: payload.name,
                    permissions: payload.permissions && typeof payload.permissions === "object"
                        ? payload.permissions
                        : {},
                    entryYear: typeof payload.entryYear === "number" ? payload.entryYear : null,
                    exp: payload.exp,
                };
            }
            catch {
                return null;
            }
        },
        permOf(session, serviceId = config.serviceId) {
            if (!session)
                return { ...DEFAULT_PERMISSION };
            return session.permissions?.[serviceId] ?? { ...DEFAULT_PERMISSION };
        },
    };
}
