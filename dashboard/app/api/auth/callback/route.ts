import { NextRequest, NextResponse } from "next/server";

import { serverConfig } from "@/lib/config";
import {
  consumeOidc,
  ensureCsrfToken,
  verifyAccessToken,
  writeTokens,
} from "@/lib/session";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const config = serverConfig();
  const code = request.nextUrl.searchParams.get("code");
  const suppliedState = request.nextUrl.searchParams.get("state");
  const suppliedIssuer = request.nextUrl.searchParams.get("iss");
  const transaction = await consumeOidc();
  if (!code || !suppliedState || suppliedState !== transaction.state || !transaction.verifier) {
    return NextResponse.redirect(`${config.appUrl}/access-denied?reason=oidc_state`);
  }
  // RFC 9207 issuer check: rejects a callback answered by anything other
  // than the configured Keycloak realm (defense against authorization
  // response mix-up when more than one OIDC provider could plausibly hit
  // this same callback URL).
  if (suppliedIssuer && suppliedIssuer !== config.issuer) {
    return NextResponse.redirect(`${config.appUrl}/access-denied?reason=iss_mismatch`);
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    redirect_uri: `${config.appUrl}/api/auth/callback`,
    code,
    code_verifier: transaction.verifier,
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
  if (!response.ok) {
    return NextResponse.redirect(`${config.appUrl}/access-denied?reason=token_exchange`);
  }
  const value = (await response.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    expires_in: number;
  };
  try {
    await verifyAccessToken(value.access_token);
  } catch {
    return NextResponse.redirect(`${config.appUrl}/access-denied?reason=invalid_token`);
  }
  await writeTokens({
    accessToken: value.access_token,
    refreshToken: value.refresh_token,
    idToken: value.id_token,
    expiresAt: Math.floor(Date.now() / 1000) + value.expires_in,
  });
  await ensureCsrfToken();
  return NextResponse.redirect(config.appUrl);
}
