import { NextResponse } from "next/server";

import { ensureCsrfToken, readUserSession } from "@/lib/session";

export async function GET(): Promise<NextResponse> {
  const session = await readUserSession();
  if (!session) {
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }
  const csrfToken = await ensureCsrfToken();
  return NextResponse.json(
    { authenticated: true, user: session, csrfToken },
    { headers: { "Cache-Control": "no-store" } },
  );
}
