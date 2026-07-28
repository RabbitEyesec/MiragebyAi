import { NextRequest, NextResponse } from "next/server";

import { serverConfig } from "@/lib/config";
import {
  clearSession,
  csrfCookie,
  readTokens,
  refreshTokens,
} from "@/lib/session";

type Context = { params: Promise<{ path: string[] }> };
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function proxy(request: NextRequest, context: Context): Promise<Response> {
  const { path } = await context.params;
  if (!path.length || path.includes("..") || path.some((part) => part.includes("\\"))) {
    return NextResponse.json({ detail: "invalid API path" }, { status: 400 });
  }
  if (MUTATING.has(request.method)) {
    const origin = request.headers.get("origin");
    const expectedOrigin = new URL(serverConfig().appUrl).origin;
    const suppliedCsrf = request.headers.get("x-csrf-token");
    if (!origin || origin !== expectedOrigin || !suppliedCsrf || suppliedCsrf !== (await csrfCookie())) {
      return NextResponse.json({ detail: "CSRF validation failed" }, { status: 403 });
    }
  }
  let tokens = await readTokens();
  if (!tokens) {
    return NextResponse.json({ detail: "authentication required" }, { status: 401 });
  }
  const target = new URL(
    `/api/${path.map(encodeURIComponent).join("/")}`,
    serverConfig().apiUrl,
  );
  target.search = request.nextUrl.search;
  const forward = async (accessToken: string) => {
    const headers = new Headers({
      accept: request.headers.get("accept") ?? "application/json",
      authorization: `Bearer ${accessToken}`,
    });
    for (const name of ["content-type", "idempotency-key", "last-event-id"]) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
    return fetch(target, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method)
        ? undefined
        : await request.arrayBuffer(),
      redirect: "manual",
      cache: "no-store",
    });
  };
  let response = await forward(tokens.accessToken);
  if (response.status === 401) {
    tokens = await refreshTokens(tokens);
    if (!tokens) {
      await clearSession();
      return NextResponse.json({ detail: "session expired" }, { status: 401 });
    }
    response = await forward(tokens.accessToken);
  }
  const headers = new Headers();
  for (const name of ["content-type", "content-disposition", "cache-control"]) {
    const value = response.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
