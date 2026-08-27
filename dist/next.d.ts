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
export declare function createTpassNextAuth(config: TpassAuthConfig): TpassNextAuth;
export type { TPassClaims, TpassAuthConfig } from "./types.js";
export { configFromEnv } from "./index.js";
