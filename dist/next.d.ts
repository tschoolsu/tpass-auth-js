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
     * 用法：`export const POST = tpass.logoutHandler;`
     */
    logoutHandler(): Promise<Response>;
}
export declare function createTpassNextAuth(config: TpassAuthConfig): TpassNextAuth;
export type { TPassClaims, TpassAuthConfig } from "./types.js";
export { configFromEnv } from "./index.js";
