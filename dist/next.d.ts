import { type TpassAuth } from "./index.js";
import type { TPassClaims, TpassAuthConfig } from "./types.js";
export interface TpassNextAuth extends TpassAuth {
    /** 讀目前 session：驗自己網域的 host-only cookie。沒有或驗不過都回 null。 */
    getSession(): Promise<TPassClaims | null>;
    /**
     * POST /api/auth/callback —— 接住 auth 用 form_post 交付的 per-service token。
     * 驗章通過才寫進本服務自己的 host-only cookie；token 全程不進 URL。
     *
     * 用法：`export const POST = tpass.callbackHandler;`
     */
    callbackHandler(request: Request): Promise<Response>;
    /**
     * POST /api/auth/logout —— 兩段式登出：先清自己的 cookie，
     * 再回一頁自動送出的 form POST 到 auth 清登入態，auth 再導回本服務。
     *
     * 表單可帶站內路徑 `next`：登出後回到指定頁而不是根路徑（「切換帳號」需要它——
     * 根路徑未登入通常會自動導去 authorize，使用者根本來不及選帳號）。
     * 沒有 body、或 body 不是表單編碼，一樣要能登出，不會因為讀 body 失敗就 500。
     *
     * 用法：`export const POST = tpass.logoutHandler;`
     */
    logoutHandler(request?: Request): Promise<Response>;
}
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
export declare function safeNextPath(next: string, selfUrl: string): string;
export declare function createTpassNextAuth(config: TpassAuthConfig): TpassNextAuth;
export type { TPassClaims, TpassAuthConfig } from "./types.js";
export { configFromEnv } from "./index.js";
