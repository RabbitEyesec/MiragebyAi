import "server-only";

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import { serverConfig } from "@/lib/config";

const SESSION_COOKIE = "__Host-mirage-session";
const REFRESH_COOKIE = "__Host-mirage-refresh";
const ID_TOKEN_COOKIE = "__Host-mirage-idtoken";
const STATE_COOKIE = "__Host-mirage-oidc-state";
const VERIFIER_COOKIE = "__Host-mirage-oidc-verifier";
const CSRF_COOKIE = "__Host-mirage-csrf";

export interface SessionTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
}

export interface UserSession {
  subject: string;
  username: string;
  roles: string[];
  expiresAt: number;
}

function key(): Buffer {
  return createHash("sha256").update(serverConfig().sessionSecret).digest();
}

function cookieOptions(httpOnly = true) {
  return {
    // __Host- prefixed cookie names require Secure on the Set-Cookie header
    // itself or browsers silently refuse to store them — true unconditionally,
    // not gated on NODE_ENV, since http://localhost is a secure context in
    // every modern browser and this must also work under plain `next dev`.
    httpOnly,
    secure: true,
    sameSite: "lax" as const,
    path: "/",
  };
}

// next/headers's cookies().delete(name) sends a Set-Cookie with no Path or
// Secure attribute at all — for a __Host- prefixed name, browsers reject
// that deletion outright (same rule that requires Secure to set one in the
// first place), so the original cookie silently survives until it expires
// on its own. Every deletion in this file must go through this helper
// instead of a bare .delete(name).
function deleteCookie(
  store: Awaited<ReturnType<typeof cookies>>,
  name: string,
): void {
  store.delete({ name, ...cookieOptions() });
}

function sealString(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64url");
}

function unsealString(value: string): string | null {
  try {
    const packed = Buffer.from(value, "base64url");
    const iv = packed.subarray(0, 12);
    const tag = packed.subarray(12, 28);
    const ciphertext = packed.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", key(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

export async function readTokens(): Promise<SessionTokens | null> {
  const store = await cookies();
  const sessionValue = store.get(SESSION_COOKIE)?.value;
  if (!sessionValue) return null;
  const decrypted = unsealString(sessionValue);
  if (!decrypted) return null;
  let parsed: { accessToken: string; expiresAt: number };
  try {
    parsed = JSON.parse(decrypted) as { accessToken: string; expiresAt: number };
  } catch {
    return null;
  }
  const refreshValue = store.get(REFRESH_COOKIE)?.value;
  const idValue = store.get(ID_TOKEN_COOKIE)?.value;
  return {
    accessToken: parsed.accessToken,
    expiresAt: parsed.expiresAt,
    refreshToken: refreshValue ? unsealString(refreshValue) ?? undefined : undefined,
    idToken: idValue ? unsealString(idValue) ?? undefined : undefined,
  };
}

export async function writeTokens(tokens: SessionTokens): Promise<void> {
  const store = await cookies();
  // Keycloak's access/refresh/id tokens carry this dev realm's 8 roles plus
  // standard claims and easily exceed a browser's 4096-byte per-cookie limit
  // when encrypted together in one blob — the cookie is then silently
  // dropped (no error, no exception; it just never appears in the jar), and
  // every "successful" login quietly reverts to logged-out on the very next
  // request. Splitting one token per cookie keeps each one comfortably
  // under that limit regardless of how many roles/claims a realm grows to.
  const maxAge = Math.max(60, tokens.expiresAt - Math.floor(Date.now() / 1000) + 86400);
  const options = { ...cookieOptions(), maxAge };
  store.set(
    SESSION_COOKIE,
    sealString(JSON.stringify({ accessToken: tokens.accessToken, expiresAt: tokens.expiresAt })),
    options,
  );
  if (tokens.refreshToken) {
    store.set(REFRESH_COOKIE, sealString(tokens.refreshToken), options);
  } else {
    deleteCookie(store, REFRESH_COOKIE);
  }
  if (tokens.idToken) {
    store.set(ID_TOKEN_COOKIE, sealString(tokens.idToken), options);
  } else {
    deleteCookie(store, ID_TOKEN_COOKIE);
  }
}

export async function clearSession(): Promise<void> {
  const store = await cookies();
  for (const name of [
    SESSION_COOKIE,
    REFRESH_COOKIE,
    ID_TOKEN_COOKIE,
    STATE_COOKIE,
    VERIFIER_COOKIE,
    CSRF_COOKIE,
  ]) {
    deleteCookie(store, name);
  }
}

export async function beginOidc(state: string, verifier: string): Promise<void> {
  const store = await cookies();
  store.set(STATE_COOKIE, state, { ...cookieOptions(), maxAge: 600 });
  store.set(VERIFIER_COOKIE, verifier, { ...cookieOptions(), maxAge: 600 });
}

export async function consumeOidc(): Promise<{ state?: string; verifier?: string }> {
  const store = await cookies();
  const result = {
    state: store.get(STATE_COOKIE)?.value,
    verifier: store.get(VERIFIER_COOKIE)?.value,
  };
  deleteCookie(store, STATE_COOKIE);
  deleteCookie(store, VERIFIER_COOKIE);
  return result;
}

export async function ensureCsrfToken(): Promise<string> {
  const store = await cookies();
  const existing = store.get(CSRF_COOKIE)?.value;
  if (existing) return existing;
  const value = randomBytes(32).toString("base64url");
  store.set(CSRF_COOKIE, value, { ...cookieOptions(false), maxAge: 86400 });
  return value;
}

export async function csrfCookie(): Promise<string | undefined> {
  return (await cookies()).get(CSRF_COOKIE)?.value;
}

function roles(payload: JWTPayload): string[] {
  const realmAccess = payload.realm_access;
  if (
    typeof realmAccess === "object" &&
    realmAccess !== null &&
    "roles" in realmAccess &&
    Array.isArray(realmAccess.roles)
  ) {
    return realmAccess.roles.filter((role): role is string => typeof role === "string");
  }
  return [];
}

export async function verifyAccessToken(token: string): Promise<JWTPayload> {
  const config = serverConfig();
  const jwks = createRemoteJWKSet(
    new URL(`${config.issuerInternal}/protocol/openid-connect/certs`),
  );
  const result = await jwtVerify(token, jwks, {
    issuer: config.issuer,
    algorithms: ["RS256"],
  });
  return result.payload;
}

export async function readUserSession(): Promise<UserSession | null> {
  const tokens = await readTokens();
  if (!tokens) return null;
  try {
    const payload = await verifyAccessToken(tokens.accessToken);
    return {
      subject: payload.sub ?? "",
      username:
        typeof payload.preferred_username === "string"
          ? payload.preferred_username
          : payload.sub ?? "unknown",
      roles: roles(payload),
      expiresAt: tokens.expiresAt,
    };
  } catch {
    return null;
  }
}

export async function refreshTokens(tokens: SessionTokens): Promise<SessionTokens | null> {
  if (!tokens.refreshToken) return null;
  const config = serverConfig();
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: config.clientId,
    refresh_token: tokens.refreshToken,
  });
  if (config.clientSecret) body.set("client_secret", config.clientSecret);
  const response = await fetch(
    `${config.issuerInternal}/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
      cache: "no-store",
    },
  );
  if (!response.ok) return null;
  const value = (await response.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    expires_in: number;
  };
  const refreshed = {
    accessToken: value.access_token,
    refreshToken: value.refresh_token ?? tokens.refreshToken,
    idToken: value.id_token ?? tokens.idToken,
    expiresAt: Math.floor(Date.now() / 1000) + value.expires_in,
  };
  await writeTokens(refreshed);
  return refreshed;
}

export const sessionCookieNames = {
  session: SESSION_COOKIE,
  refresh: REFRESH_COOKIE,
  idToken: ID_TOKEN_COOKIE,
  state: STATE_COOKIE,
  verifier: VERIFIER_COOKIE,
  csrf: CSRF_COOKIE,
};
