import { afterEach, describe, expect, it, vi } from "vitest";

import { api, ApiError } from "@/services/api";
import { model } from "@/tests/fixtures";

describe("dashboard API client", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns the canonical case model", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(JSON.stringify(model), { status: 200, headers: { "content-type": "application/json" } }),
    ));
    await expect(api.case(model.summary.case_id)).resolves.toEqual(model);
  });

  it("uses bounded error details without leaking upstream HTML", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response("<html>stack trace</html>", { status: 503, statusText: "Unavailable" }),
    ));
    await expect(api.case("unknown")).rejects.toEqual(
      new ApiError(503, "Unavailable"),
    );
  });
});
