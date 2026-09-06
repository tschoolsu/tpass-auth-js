// Next.js（App Router）專用的糖：讀 cookie 的 getSession，以及 callback / logout
// 兩條 route handler——那兩個檔以前也是每個服務手抄一份。
//
// 這裡刻意只依賴 `next/headers`：回應一律用標準 Response 自己組（含 Set-Cookie），
// 不碰 NextResponse，這樣套件不會被綁死在某個 Next 版本的 API 上。
import { cookies } from "next/headers";
import { createTpassAuth } from "./index.js";
const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
/**
 * 判斷 `next` 是否為站內路徑，是就回傳可安全使用的路徑，不是就回 `/`。
 *
 * 兩段式檢查，缺一都會被繞過：
 *
 * 1. **輸入階段：origin 比對。** 不能只檢查字串開頭是不是單一 `/`：WHATWG URL
 *    對 http(s) 這類 special scheme 會把 `\` 正規化成 `/`，所以
 *    `new URL("/\\evil.invalid/x", selfUrl)` 會解析成 `https://evil.invalid/x`——
 *    字串檢查騙得過，但 URL 已經跑到別的網域。因此判斷一律用「解析後的 origin
 *    是否等於 selfUrl 的 origin」，而不是原字串長相。
 * 2. **輸出階段：擋 `//` 開頭。**（A4-1 補修）步驟 1 只保證「這次解析」沒有跑出
 *    origin，但 `..`／反斜線／百分號編碼在正規化路徑段時會互相疊加，把
 *    `/..//evil.example` 這類字串的 pathname 收斂成 `//evil.example`——這一步
 *    origin 仍然等於 selfUrl（因為 `..` 已經被吃掉、根本沒跑出去），檢查騙不了。
 *    但呼叫端（callbackHandler／logoutHandler）會拿這個回傳值**再解析一次**
 *    `new URL(safeNext, selfUrl)`，而 `//evil.example` 是合法的 protocol-relative
 *    URL：第二次解析會把它當成「沿用 selfUrl 的 scheme、換成 evil.example 的
 *    host」，這才真正跑出網域。所以輸出本身也不能以 `//` 開頭，這裡直接對
 *    「正規化後的 pathname」補一刀，不是對使用者原始輸入補——原始輸入長怎樣不重要，
 *    重要的是丟給第二次 `new URL()` 的字串必須安全。
 *
 * 修完之後輸出只有一種形狀：以單一 `/` 開頭、不含 `\`、`..` 已被收斂，是不動點——
 * `safeNextPath(safeNextPath(x, self), self) === safeNextPath(x, self)`。
 */
export function safeNextPath(next, selfUrl) {
    if (!next.startsWith("/") || next.startsWith("//"))
        return "/";
    let url;
    try {
        url = new URL(next, selfUrl);
    }
    catch {
        return "/";
    }
    if (url.origin !== new URL(selfUrl).origin)
        return "/";
    const path = `${url.pathname}${url.search}${url.hash}`;
    // pathname 正規化後可能收斂成 // 開頭（/..//evil.example 之類），
    // 這種字串丟進第二次 new URL() 會被當成 protocol-relative 跑出 origin。
    if (path.startsWith("//"))
        return "/";
    return path;
}
function cookieHeader(name, value, opts) {
    const parts = [
        `${name}=${value}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        `Max-Age=${opts.maxAge}`,
    ];
    // 不設 Domain → host-only：別的子網域收不到，這就是契約 v2 的隔離來源。
    if (opts.secure)
        parts.push("Secure");
    return parts.join("; ");
}
export function createTpassNextAuth(config) {
    const auth = createTpassAuth(config);
    return {
        ...auth,
        async getSession() {
            const token = (await cookies()).get(auth.cookieName)?.value;
            if (!token)
                return null;
            return auth.verifyToken(token);
        },
        async callbackHandler(request) {
            const form = await request.formData();
            const token = form.get("token");
            const next = String(form.get("next") ?? "/");
            if (typeof token !== "string" || !token) {
                return new Response("Bad request", { status: 400 });
            }
            // 安全四鐵則驗章（aud = 本服務專屬）；驗不過一律 401，不留線索。
            const claims = await auth.verifyToken(token);
            if (!claims)
                return new Response("Invalid token", { status: 401 });
            // next 只能是站內路徑（防 Open Redirect）。
            const safeNext = safeNextPath(next, auth.selfUrl);
            return new Response(null, {
                status: 303,
                headers: {
                    Location: new URL(safeNext, auth.selfUrl).toString(),
                    "Set-Cookie": cookieHeader(auth.cookieName, token, {
                        // cookie 壽命跟著 token 走，不多不少。
                        maxAge: Math.max(0, claims.exp - Math.floor(Date.now() / 1000)),
                        secure: auth.cookieSecure,
                    }),
                },
            });
        },
        async logoutHandler(request) {
            let next = "/";
            if (request) {
                try {
                    next = String((await request.formData()).get("next") ?? "/");
                }
                catch {
                    // 沒有 body 或不是表單編碼——照樣登出，回根路徑。
                }
            }
            // next 只能是站內路徑（防 Open Redirect）——與 callback 同一條規則。
            const safeNext = safeNextPath(next, auth.selfUrl);
            const returnTo = new URL(safeNext, auth.selfUrl).toString();
            const authLogout = `${auth.authLogoutUrl}?redirect_uri=${encodeURIComponent(returnTo)}`;
            const html = `<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><title>登出中…</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="${escapeHtml(authLogout)}">
<noscript><button type="submit">完成登出</button></noscript>
</form>
</body></html>`;
            return new Response(html, {
                headers: {
                    "content-type": "text/html; charset=utf-8",
                    "cache-control": "no-store",
                    "Set-Cookie": cookieHeader(auth.cookieName, "", {
                        maxAge: 0,
                        secure: auth.cookieSecure,
                    }),
                },
            });
        },
    };
}
export { configFromEnv } from "./index.js";
