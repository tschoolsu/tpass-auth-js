/** role 三級；admin 隱含 moderator。 */
export type Role = "admin" | "moderator" | "default";
/** 管制狀態；省略等於 none。 */
export type Restriction = "none" | "warning" | "ban";
/** 某人在「某一個服務」的權限。 */
export interface PermissionEntry {
    /** 必有。唯一必看欄位（＝ restriction !== "ban"），auth 已經算好。 */
    read: boolean;
    /** 必有。admin 隱含 moderator。 */
    role: Role;
    /** 省略 = none。 */
    restriction?: Restriction;
    /** 只在 restriction !== "none" 時出現。 */
    reason?: string;
    /** 選填 Unix 秒，管制到期自動解除。 */
    until?: number;
}
export type PermissionMap = Record<string, PermissionEntry>;
/** 驗章通過後拿到的身分。 */
export interface TPassClaims {
    sub: string;
    email: string;
    name: string;
    /**
     * per-service 權限本體。一般服務的 token 只含自己 serviceId 一把 key；
     * 若本服務在 auth 的 AUTH_OVERVIEW_SERVICE_IDS（門戶）內，會帶全服務 map（含 "auth"）。
     */
    permissions: PermissionMap;
    /**
     * 民國入學學年度（契約 v2）。老師／職務帳號與舊 token 沒有這個欄位 → null，
     * 需要年級的服務自行從信箱 fallback 推算。
     */
    entryYear: number | null;
    exp: number;
}
/**
 * 消費端設定。全部 env 驅動，網域一律不寫死（見 configFromEnv）。
 */
export interface TpassAuthConfig {
    /** auth 的 JWKS 公鑰端點（只讀公鑰，永遠不碰私鑰）。 */
    jwksUrl: string;
    /** 必須與 auth 簽發端完全一致（含 port、無多餘斜線）。 */
    issuer: string;
    /** 本服務登記在 tpass-registry 的 id；audience 由它派生成 `tpass:<id>`。 */
    serviceId: string;
    /** 本服務自己的完整網址（callback 導回、cookie secure 判斷用）。 */
    selfUrl: string;
    /** auth 的 authorize 入口。 */
    authorizeUrl: string;
    /** auth 的登出入口。 */
    authLogoutUrl: string;
    /** 選填：ban 頁；未設就用 authorizeUrl 的 origin + /denied。 */
    deniedUrl?: string;
    /** 選填：本服務自己的 cookie 名稱，預設 tpass_token。 */
    cookieName?: string;
}
