import { describe, expect, it } from "vitest";

import { formatGbp, truncate } from "@/lib/format";

describe("safe formatting", () => {
  it("formats budget values in GBP", () => {
    expect(formatGbp("12.3456")).toContain("£12.3456");
  });

  it("truncates without interpreting HTML", () => {
    expect(truncate("<script>alert(1)</script>", 12)).toBe("<script>ale…");
  });
});
