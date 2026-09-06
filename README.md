# tpass-auth-js

T-Pass SSO **消費端**驗章套件（契約 v2）。一行 import 取代以前每個服務手抄一份的
`src/lib/tpass-auth.ts` + `api/auth/callback` + `api/auth/logout`。

> 權威合約在 [`tpass-auth/INTEGRATION.md`](https://github.com/tschoolsu/tpass-auth/blob/main/INTEGRATION.md)。
> 這個 README 只講怎麼用這個套件，不重述合約。

## 為什麼有這個套件

驗章有四道檢查，缺一不可：

1. `algorithms: ["EdDSA"]` —— 不鎖會有 alg confusion 偽造風險
2. `issuer` —— 票是「這個 auth」簽的
3. `audience === tpass:<本服務id>` —— 票是簽給**我**的
4. `exp` —— 沒過期

**漏掉任何一項，登入都照樣成功、測試也不會紅**，只有在別人拿其他服務的通行證來打你的
時候才會發現。這種安靜的錯誤不能靠人類抄寫來防守，所以它們現在住在一個有測試的地方。

## 安裝

```bash
pnpm add github:tschoolsu/tpass-auth-js#v1.1.1
pnpm add jose            # peer dependency
```

版本一律**釘 tag**（`#v1.1.1`），不要用 `#main`。

## 用法（Next.js App Router）

`src/config/auth.ts`——整個服務只有這裡認識 env：

```ts
import "server-only";
import { createTpassNextAuth, configFromEnv } from "tpass-auth-js/next";

// 缺 env 就直接 throw（fail closed）。第一個參數是「本服務自己的網址」那顆 env 的名字。
export const tpass = createTpassNextAuth(configFromEnv("FORM_SELF_URL"));
```

需要的 env（值一律 env 驅動，**永遠不要把網域寫死在程式裡**）：
`AUTH_JWKS_URL`、`AUTH_AUTHORIZE_URL`、`AUTH_LOGOUT_URL`、`TPASS_SERVICE_ID`、
`JWT_ISSUER`、以及你自己的 `<SVC>_SELF_URL`。選填 `AUTH_DENIED_URL`。

頁面（server component）：

```ts
import { redirect } from "next/navigation";
import { tpass } from "@/config/auth";

export default async function Page() {
  const session = await tpass.getSession();
  if (!session) redirect(tpass.loginUrl("/"));          // 未登入 → 去換票

  const perm = tpass.permOf(session);                    // 本服務的權限
  if (!perm.read) redirect(tpass.deniedUrl());           // 被 ban
  if (perm.role === "admin") { /* … */ }

  return <p>{session.name}</p>;
}
```

兩條 route，各一行：

```ts
// src/app/api/auth/callback/route.ts
import { tpass } from "@/config/auth";
export const runtime = "nodejs";
export const POST = tpass.callbackHandler;
```

```ts
// src/app/api/auth/logout/route.ts
import { tpass } from "@/config/auth";
export const runtime = "nodejs";
export const POST = tpass.logoutHandler;
```

登出表單可以帶一個站內路徑 `next`（登出後回到那一頁而不是根路徑，「切換帳號」需要它）；callback 也支援。判斷是否為站內路徑一律用解析後的 origin 比對（`safeNextPath`），不是字串開頭長相，防止反斜線變體之類繞過 open redirect 防護。

## 不是 Next.js？

主要進入點 `tpass-auth-js` 只依賴 `jose`，沒有任何框架相依：

```ts
import { createTpassAuth } from "tpass-auth-js";

const tpass = createTpassAuth({ jwksUrl, issuer, serviceId, selfUrl, authorizeUrl, authLogoutUrl });
const session = await tpass.verifyToken(tokenFromYourOwnCookie);
```

`tpass-auth-js/next` 只是在它之上加了 `getSession()` 與那兩條 route handler。

JWKS 快取預設 `cacheMaxAge` 24 小時（D10-1；jose 6 原生預設只有 10 分鐘，auth 短暫中斷或本服務被重啟打掉記憶體快取就會逼全部驗章立刻重抓、抓不到就整批失敗），需要的話用 `jwksOptions` 選填覆寫 `cacheMaxAge` / `cooldownDuration` / `timeoutDuration`。換金鑰時只要 kid 也換掉就不受這 24 小時影響（kid 不符會照樣立即重抓，只受 `cooldownDuration` 限制）。

## 紅線

- ❌ 不要在前端驗章、不要把 token 塞 `localStorage`（cookie 是 HttpOnly，本來就拿不到）。
- ❌ 不要為了「暫時能動」去改 `algorithms` / `issuer` / `audience` 任何一項。
- ❌ 消費端 cookie 不要設 `Domain=.<根網域>`（那是已經退場的 v1）。
- ✅ 權限一律讀 `permissions` claim（`tpass.permOf`），各服務不自維護 admin 名單。

## 開發

```bash
pnpm install
pnpm test          # 驗章四鐵則的迴歸測試（自架假 JWKS，真的簽/驗）
pnpm run build     # 產出 dist/，dist 直接進 git
```

`dist/` 進版控是刻意的：消費端與主機用 git URL 安裝，這樣 install 時不必編譯任何東西。
**所以這個套件沒有 `prepare` script**——有的話 pnpm 會要求每個消費端把它加進
`onlyBuiltDependencies` 白名單才肯安裝。代價是「改了 src 忘了 build」，那件事由 CI 擋
（`git diff --exit-code -- dist`）。改完 src 一定要跑一次 `pnpm run build` 再 commit。
