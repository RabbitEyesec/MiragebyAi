import { createHash, randomBytes } from "node:crypto";
import { NextResponse } from "next/server";

import { serverConfig } from "@/lib/config";
import { beginOidc, clearSession } from "@/lib/session";

export async function GET(): Promise<NextResponse> {
  const config = serverConfig();
  // Starting a fresh OIDC transaction always wins over whatever is left from
  // a previous attempt — a stale session/state/verifier/csrf cookie from an
  // earlier failed or abandoned login must never confuse this one.
  await clearSession();
  const state = randomBytes(32).toString("base64url");
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  await beginOidc(state, verifier);
  const authorize = new URL(
    `${config.issuer}/protocol/openid-connect/auth`,
  );
  authorize.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: `${config.appUrl}/api/auth/callback`,
    response_type: "code",
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return NextResponse.redirect(authorize);
}
