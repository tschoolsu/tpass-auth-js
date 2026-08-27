// Next.js（App Router）專用的糖：讀 cookie 的 getSession，以及 callback / logout
// 兩條 route handler——那兩個檔以前也是每個服務手抄一份。
//
// 這裡刻意只依賴 `next/headers`：回應一律用標準 Response 自己組（含 Set-Cookie），
// 不碰 NextResponse，這樣套件不會被綁死在某個 Next 版本的 API 上。
import { cookies } from "next/headers";
import { createTpassAuth, type TpassAuth } from "./index.js";
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

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function cookieHeader(
  name: string,
  value: string,
  opts: { maxAge: number; secure: boolean },
): string {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${opts.maxAge}`,
  ];
  // 不設 Domain → host-only：別的子網域收不到，這就是契約 v2 的隔離來源。
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

export function createTpassNextAuth(config: TpassAuthConfig): TpassNextAuth {
  const auth = createTpassAuth(config);

  return {
    ...auth,

    async getSession() {
      const token = (await cookies()).get(auth.cookieName)?.value;
      if (!token) return null;
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
      if (!claims) return new Response("Invalid token", { status: 401 });

      // next 只能是站內路徑（防 Open Redirect）。
      const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/";

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
        } catch {
          // 沒有 body 或不是表單編碼——照樣登出，回根路徑。
        }
      }
      // next 只能是站內路徑（防 Open Redirect）——與 callback 同一條規則。
      const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/";
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

export type { TPassClaims, TpassAuthConfig } from "./types.js";
export { configFromEnv } from "./index.js";
