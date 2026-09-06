import type { PermissionEntry, TPassClaims, TpassAuthConfig } from "./types.js";
export type { JwksCacheOptions, PermissionEntry, PermissionMap, Restriction, Role, TPassClaims, TpassAuthConfig, } from "./types.js";
export interface TpassAuth {
    /** 本服務的 id（＝ tpass-registry 的 id）。 */
    readonly serviceId: string;
    /** 本服務專屬 audience：`tpass:<serviceId>`。 */
    readonly audience: string;
    /** 本服務自己的 host-only cookie 名稱。 */
    readonly cookieName: string;
    /** selfUrl 是 https 才在 cookie 上設 Secure（本機 http 開發不會被瀏覽器丟掉）。 */
    readonly cookieSecure: boolean;
    readonly selfUrl: string;
    readonly issuer: string;
    /** auth 的 origin（/admin、/denied 都掛在它底下）。 */
    readonly authOrigin: string;
    /** auth 的權限管理 panel。 */
    readonly adminUrl: string;
    /** 本服務自己的登出 route（清自己的 cookie，再鏈到 auth）。 */
    readonly logoutUrl: string;
    /** auth 端的登出入口。 */
    readonly authLogoutUrl: string;
    /** 未登入時要導去的 authorize 入口；returnPath 是登入後回到的站內路徑。 */
    loginUrl(returnPath?: string): string;
    /** read === false（被 ban）時導去的頁面。 */
    deniedUrl(serviceId?: string): string;
    /**
     * 驗一個 token（安全四鐵則）。失敗（過期／竄改／錯 iss／錯 aud／錯演算法）
     * 一律回 null，不外拋、不透露原因。
     */
    verifyToken(token: string): Promise<TPassClaims | null>;
    /** 讀某人在某服務的權限；不傳 serviceId 就是「本服務」。 */
    permOf(session: TPassClaims | null | undefined, serviceId?: string): PermissionEntry;
}
/**
 * 從標準環境變數組出設定。各服務的「自己的網址」env 名稱不同（FORM_SELF_URL、
 * PORTAL_SELF_URL…），所以那一顆的名字要傳進來。
 *
 * 缺值就直接 throw（fail closed）：與其讓服務帶著半套設定跑起來、在第一次登入時
 * 靜默鬼打牆，不如啟動就炸並列出缺哪幾顆。
 */
export declare function configFromEnv(selfUrlEnvName: string, env?: Record<string, string | undefined>): TpassAuthConfig;
/**
 * 建一個綁定本服務設定的驗章器。一個服務建一次（模組層級 const），
 * 這樣 JWKS 的記憶體快取才會共用。
 */
export declare function createTpassAuth(config: TpassAuthConfig): TpassAuth;
