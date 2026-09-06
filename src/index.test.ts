// 驗章四鐵則的迴歸測試。
//
// 這些測試就是這個套件存在的理由：以前六個服務各抄一份驗章邏輯，抄漏 audience
// 不會有任何測試失敗、登入照樣成功——只有別人拿其他服務的通行證來打時才會發現。
// 現在漏掉任何一鐵則，這裡就會紅。
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair, createRemoteJWKSet, type JWK } from "jose";
import { createTpassAuth, configFromEnv } from "./index.js";

// createRemoteJWKSet 換成「照樣運作、但記得每次呼叫參數」的 spy，
// 這樣既能測 D10-1 的快取選項，也不影響上面驗章邏輯的其他測試。
vi.mock("jose", async (importOriginal) => {
  const actual = await importOriginal<typeof import("jose")>();
  return { ...actual, createRemoteJWKSet: vi.fn(actual.createRemoteJWKSet) };
});

const ISSUER = "https://auth.test.invalid";
const SERVICE = "form";

let server: Server;
let jwksUrl: string;
let privateKey: CryptoKey;
let publicJwk: JWK;

async function sign(
  claims: Record<string, unknown>,
  opts: { aud?: string; iss?: string; exp?: string | number } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: "test-key" })
    .setIssuer(opts.iss ?? ISSUER)
    .setAudience(opts.aud ?? `tpass:${SERVICE}`)
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? "5m")
    .sign(privateKey);
}

beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  privateKey = kp.privateKey;
  publicJwk = { ...(await exportJWK(kp.publicKey)), kid: "test-key", alg: "EdDSA", use: "sig" };

  // 假的 auth：只提供 JWKS 公鑰端點，跟真的 auth 一樣不做任何回呼。
  server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [publicJwk] }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  jwksUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/jwks.json`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

function auth(serviceId = SERVICE) {
  return createTpassAuth({
    jwksUrl,
    issuer: ISSUER,
    serviceId,
    selfUrl: "https://form.test.invalid",
    authorizeUrl: `${ISSUER}/api/auth/authorize`,
    authLogoutUrl: `${ISSUER}/api/auth/logout`,
  });
}

const CLAIMS = {
  sub: "u1",
  email: "someone@school.invalid",
  name: "某同學",
  permissions: { [SERVICE]: { read: true, role: "admin" } },
};

describe("verifyToken", () => {
  it("正常的票驗得過，claims 原樣帶出來", async () => {
    const s = await auth().verifyToken(await sign(CLAIMS));
    expect(s).not.toBeNull();
    expect(s!.sub).toBe("u1");
    expect(s!.email).toBe("someone@school.invalid");
    expect(s!.permissions[SERVICE]!.role).toBe("admin");
    // 沒帶 entryYear 的票 → null（不是 undefined、不是 0）
    expect(s!.entryYear).toBeNull();
  });

  it("entryYear 是數字才採信", async () => {
    const ok = await auth().verifyToken(await sign({ ...CLAIMS, entryYear: 114 }));
    expect(ok!.entryYear).toBe(114);
    const bad = await auth().verifyToken(await sign({ ...CLAIMS, entryYear: "114" }));
    expect(bad!.entryYear).toBeNull();
  });

  // ── 鐵則 3：別的服務的票必須驗不過（爆炸半徑隔離）────────────────
  it("拿 appeals 的票來打 form，驗不過", async () => {
    const token = await sign(CLAIMS, { aud: "tpass:appeals" });
    expect(await auth().verifyToken(token)).toBeNull();
  });

  // ── 鐵則 2：issuer ──────────────────────────────────────────────
  it("別的 auth 簽的票驗不過", async () => {
    const token = await sign(CLAIMS, { iss: "https://evil.test.invalid" });
    expect(await auth().verifyToken(token)).toBeNull();
  });

  // ── 鐵則 4：exp ────────────────────────────────────────────────
  it("過期的票驗不過", async () => {
    const token = await sign(CLAIMS, { exp: Math.floor(Date.now() / 1000) - 60 });
    expect(await auth().verifyToken(token)).toBeNull();
  });

  // ── 鐵則 1：alg 鎖定（alg confusion）────────────────────────────
  it("拿公鑰當對稱金鑰簽的 HS256 票驗不過", async () => {
    const raw = Buffer.from(JSON.stringify(publicJwk));
    const forged = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "HS256", kid: "test-key" })
      .setIssuer(ISSUER)
      .setAudience(`tpass:${SERVICE}`)
      .setExpirationTime("5m")
      .sign(new Uint8Array(raw.subarray(0, 32)));
    expect(await auth().verifyToken(forged)).toBeNull();
  });

  it("被竄改過的票驗不過", async () => {
    const token = await sign(CLAIMS);
    const [h, p, sig] = token.split(".");
    const payload = JSON.parse(Buffer.from(p!, "base64url").toString());
    payload.email = "principal@school.invalid";
    const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${sig}`;
    expect(await auth().verifyToken(tampered)).toBeNull();
  });

  it("垃圾字串驗不過而且不外拋", async () => {
    expect(await auth().verifyToken("not-a-jwt")).toBeNull();
    expect(await auth().verifyToken("")).toBeNull();
  });
});

describe("permOf", () => {
  it("沒有 session 或沒有該服務的 key → 能讀、預設角色（fail-open）", () => {
    const a = auth();
    expect(a.permOf(null)).toEqual({ read: true, role: "default" });
    expect(
      a.permOf({ sub: "u", email: "e", name: "n", permissions: {}, entryYear: null, exp: 0 }),
    ).toEqual({ read: true, role: "default" });
  });

  it("預設查本服務，也能查別的服務（門戶的 overview token）", () => {
    const a = auth("portal");
    const session = {
      sub: "u",
      email: "e",
      name: "n",
      entryYear: null,
      exp: 0,
      permissions: {
        portal: { read: true, role: "default" as const },
        auth: { read: true, role: "admin" as const },
      },
    };
    expect(a.permOf(session).role).toBe("default");
    expect(a.permOf(session, "auth").role).toBe("admin");
  });

  it("回傳的是複本，改它不會污染下一個呼叫", () => {
    const a = auth();
    const p = a.permOf(null);
    p.read = false;
    expect(a.permOf(null).read).toBe(true);
  });
});

describe("網址組法", () => {
  it("loginUrl 帶齊 service / redirect_uri / next", () => {
    const u = new URL(auth().loginUrl("/dashboard"));
    expect(u.searchParams.get("service")).toBe(SERVICE);
    expect(u.searchParams.get("redirect_uri")).toBe(
      "https://form.test.invalid/api/auth/callback",
    );
    expect(u.searchParams.get("next")).toBe("/dashboard");
  });

  it("selfUrl 尾斜線不會變成雙斜線", () => {
    const a = createTpassAuth({
      jwksUrl,
      issuer: ISSUER,
      serviceId: SERVICE,
      selfUrl: "https://form.test.invalid/",
      authorizeUrl: `${ISSUER}/api/auth/authorize`,
      authLogoutUrl: `${ISSUER}/api/auth/logout`,
    });
    expect(a.logoutUrl).toBe("https://form.test.invalid/api/auth/logout");
  });

  it("deniedUrl 預設由 authorizeUrl 的 origin 推導，且只帶 service", () => {
    const u = new URL(auth().deniedUrl());
    expect(u.origin + u.pathname).toBe(`${ISSUER}/denied`);
    expect(u.searchParams.get("service")).toBe(SERVICE);
    expect(u.searchParams.get("reason")).toBeNull();
  });

  it("http 的 selfUrl 不設 Secure cookie（本機開發），https 才設", () => {
    expect(auth().cookieSecure).toBe(true);
    const local = createTpassAuth({
      jwksUrl,
      issuer: ISSUER,
      serviceId: SERVICE,
      selfUrl: "http://localhost:3002",
      authorizeUrl: `${ISSUER}/api/auth/authorize`,
      authLogoutUrl: `${ISSUER}/api/auth/logout`,
    });
    expect(local.cookieSecure).toBe(false);
  });
});

describe("configFromEnv", () => {
  const env = {
    AUTH_JWKS_URL: "https://a/.well-known/jwks.json",
    AUTH_AUTHORIZE_URL: "https://a/api/auth/authorize",
    AUTH_LOGOUT_URL: "https://a/api/auth/logout",
    TPASS_SERVICE_ID: "form",
    JWT_ISSUER: "https://a",
    FORM_SELF_URL: "https://f",
  };

  it("讀齊六顆", () => {
    expect(configFromEnv("FORM_SELF_URL", env).serviceId).toBe("form");
  });

  it("不吃 TPASS_COOKIE_NAME（v1 遺留物，讀了會靜默退回舊 cookie 名）", () => {
    const c = configFromEnv("FORM_SELF_URL", { ...env, TPASS_COOKIE_NAME: "tpass_session" });
    expect(c.cookieName).toBeUndefined();
    expect(createTpassAuth(c).cookieName).toBe("tpass_token");
  });

  it("缺哪幾顆就講哪幾顆（fail closed）", () => {
    const { AUTH_JWKS_URL: _a, FORM_SELF_URL: _b, ...rest } = env;
    expect(() => configFromEnv("FORM_SELF_URL", rest)).toThrow(/AUTH_JWKS_URL.*FORM_SELF_URL/);
  });
});

// D10-1：jose 6 預設 cacheMaxAge 只有 10 分鐘，auth 短暫中斷（或消費端被 pm2 重啟
// 打掉記憶體快取）就會逼所有還在線的使用者立刻重抓 JWKS——抓不到就整批驗不過。
describe("JWKS 快取設定（D10-1）", () => {
  const mockedCreateRemoteJWKSet = vi.mocked(createRemoteJWKSet);

  it("預設把 cacheMaxAge 拉到 24 小時，並帶 cooldown/timeout", () => {
    mockedCreateRemoteJWKSet.mockClear();
    auth();
    expect(mockedCreateRemoteJWKSet).toHaveBeenCalledTimes(1);
    const [url, options] = mockedCreateRemoteJWKSet.mock.calls[0]!;
    expect(url).toEqual(new URL(jwksUrl));
    expect(options?.cacheMaxAge).toBe(24 * 60 * 60 * 1000);
    expect(options?.cooldownDuration).toBe(30_000);
    expect(options?.timeoutDuration).toBe(5_000);
  });

  it("可以由 config 覆寫", () => {
    mockedCreateRemoteJWKSet.mockClear();
    createTpassAuth({
      jwksUrl,
      issuer: ISSUER,
      serviceId: SERVICE,
      selfUrl: "https://form.test.invalid",
      authorizeUrl: `${ISSUER}/api/auth/authorize`,
      authLogoutUrl: `${ISSUER}/api/auth/logout`,
      jwksOptions: { cacheMaxAge: 60_000 },
    });
    const [, options] = mockedCreateRemoteJWKSet.mock.calls[0]!;
    expect(options?.cacheMaxAge).toBe(60_000);
    // 沒覆寫到的欄位維持預設，不會因為傳了部分 options 就整組被清掉。
    expect(options?.cooldownDuration).toBe(30_000);
    expect(options?.timeoutDuration).toBe(5_000);
  });
});
