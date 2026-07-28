import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";

import { serverConfig } from "@/lib/config";
import { clearSession, csrfCookie, readTokens } from "@/lib/session";

function equal(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

export async function POST(request: Request): Promise<NextResponse> {
  const config = serverConfig();
  const expectedOrigin = new URL(config.appUrl).origin;
  const suppliedOrigin = request.headers.get("origin");
  const suppliedCsrf = request.headers.get("x-csrf-token");
  const expectedCsrf = await csrfCookie();
  if (
    suppliedOrigin !== expectedOrigin ||
    !suppliedCsrf ||
    !expectedCsrf ||
    !equal(suppliedCsrf, expectedCsrf)
  ) {
    return NextResponse.json(
      { error: "CSRF validation failed" },
      { status: 403 },
    );
  }
  const tokens = await readTokens();
  await clearSession();
  const logout = new URL(
    `${config.issuer}/protocol/openid-connect/logout`,
  );
  logout.searchParams.set("client_id", config.clientId);
  logout.searchParams.set("post_logout_redirect_uri", config.appUrl);
  if (tokens?.idToken) logout.searchParams.set("id_token_hint", tokens.idToken);
  return NextResponse.json({ logoutUrl: logout.toString() });
}
