// callback / logout 兩條 route handler 的行為測試。
// 這兩個檔以前也是每個服務手抄一份，而且已經漂移過：只有 tpass-form 的登出支援
// 「登出後回到指定頁」（切換帳號要用）。現在那個行為對所有服務都成立。
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import { createTpassNextAuth } from "./next.js";

const ISSUER = "https://auth.test.invalid";
const SELF = "https://form.test.invalid";

let server: Server;
let jwksUrl: string;
let privateKey: CryptoKey;

beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  privateKey = kp.privateKey;
  const jwk: JWK = { ...(await exportJWK(kp.publicKey)), kid: "k", alg: "EdDSA", use: "sig" };
  server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  jwksUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks.json`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

function tpass() {
  return createTpassNextAuth({
    jwksUrl,
    issuer: ISSUER,
    serviceId: "form",
    selfUrl: SELF,
    authorizeUrl: `${ISSUER}/api/auth/authorize`,
    authLogoutUrl: `${ISSUER}/api/auth/logout`,
  });
}

async function token(aud = "tpass:form", ttl = "5m") {
  return new SignJWT({ sub: "u1", email: "a@b.invalid", name: "某人", permissions: {} })
    .setProtectedHeader({ alg: "EdDSA", kid: "k" })
    .setIssuer(ISSUER)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(privateKey);
}

function formPost(body: Record<string, string>) {
  return new Request(`${SELF}/api/auth/callback`, {
    method: "POST",
    body: new URLSearchParams(body),
  });
}

describe("callbackHandler", () => {
  it("驗章過 → 303 導到站內路徑，並寫 host-only cookie", async () => {
    const res = await tpass().callbackHandler(
      formPost({ token: await token(), next: "/admin" }),
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(`${SELF}/admin`);
    const cookie = res.headers.get("Set-Cookie")!;
    expect(cookie).toContain("tpass_token=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Secure");
    // 不設 Domain＝host-only：別的子網域收不到，這是契約 v2 的隔離來源。
    expect(cookie).not.toContain("Domain");
  });

  it("外部網址與 protocol-relative 的 next 都會被打回根路徑", async () => {
    for (const bad of ["https://evil.invalid/x", "//evil.invalid/x"]) {
      const res = await tpass().callbackHandler(formPost({ token: await token(), next: bad }));
      expect(res.headers.get("Location")).toBe(`${SELF}/`);
    }
  });

  it("別的服務的票 → 401，而且不寫 cookie", async () => {
    const res = await tpass().callbackHandler(
      formPost({ token: await token("tpass:appeals"), next: "/" }),
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("沒有 token → 400", async () => {
    const res = await tpass().callbackHandler(formPost({ next: "/" }));
    expect(res.status).toBe(400);
  });

  it("cookie 壽命跟著 token 的 exp 走", async () => {
    const res = await tpass().callbackHandler(formPost({ token: await token("tpass:form", "60s"), next: "/" }));
    const maxAge = Number(/Max-Age=(\d+)/.exec(res.headers.get("Set-Cookie")!)![1]);
    expect(maxAge).toBeGreaterThan(50);
    expect(maxAge).toBeLessThanOrEqual(60);
  });
});

describe("logoutHandler", () => {
  it("清掉自己的 cookie，並把 auth 的登出入口組進表單", async () => {
    const res = await tpass().logoutHandler();
    const cookie = res.headers.get("Set-Cookie")!;
    expect(cookie).toContain("tpass_token=;");
    expect(cookie).toContain("Max-Age=0");
    const html = await res.text();
    expect(html).toContain(encodeURIComponent(`${SELF}/`));
    expect(html).toContain(`${ISSUER}/api/auth/logout`);
  });

  it("表單帶 next 就登出後回那一頁（切換帳號用）", async () => {
    const req = new Request(`${SELF}/api/auth/logout`, {
      method: "POST",
      body: new URLSearchParams({ next: "/f/abc" }),
    });
    const html = await (await tpass().logoutHandler(req)).text();
    expect(html).toContain(encodeURIComponent(`${SELF}/f/abc`));
  });

  it("next 是外部網址就忽略", async () => {
    const req = new Request(`${SELF}/api/auth/logout`, {
      method: "POST",
      body: new URLSearchParams({ next: "https://evil.invalid" }),
    });
    const html = await (await tpass().logoutHandler(req)).text();
    expect(html).toContain(encodeURIComponent(`${SELF}/`));
    expect(html).not.toContain("evil.invalid");
  });

  it("沒有 body 的 POST 一樣登得出去", async () => {
    const req = new Request(`${SELF}/api/auth/logout`, { method: "POST" });
    const res = await tpass().logoutHandler(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
  });
});
