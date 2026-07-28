import { describe, expect, it } from "vitest";

import {
  initialRealtimeState,
  parseSseBlock,
  realtimeReducer,
} from "@/hooks/realtime";
import type { DashboardRealtimeUpdateV1 } from "@/models";
import { caseId } from "@/tests/fixtures";

function update(id: string): DashboardRealtimeUpdateV1 {
  return {
    update_id: id,
    update_type: "CASE_UPDATED",
    case_id: caseId,
    projection_version: 2,
    event_time: "2026-07-26T10:00:00Z",
    payload: {},
    correlation_id: id,
  };
}

describe("real-time reducer and reconnect", () => {
  it("suppresses duplicate update IDs", () => {
    const first = realtimeReducer(initialRealtimeState, { type: "UPDATE", sequence: 1, update: update("a") });
    const duplicate = realtimeReducer(first, { type: "UPDATE", sequence: 2, update: update("a") });
    expect(duplicate).toBe(first);
  });

  it("detects sequence gaps and requests a full refresh", () => {
    const first = realtimeReducer(initialRealtimeState, { type: "UPDATE", sequence: 3, update: update("a") });
    const gap = realtimeReducer(first, { type: "UPDATE", sequence: 5, update: update("b") });
    expect(gap.needsRefresh).toBe(true);
    expect(gap.lastSequence).toBe(5);
  });

  it("parses resumable SSE blocks", () => {
    const parsed = parseSseBlock(`id: 12\nevent: CASE_UPDATED\ndata: ${JSON.stringify(update("u"))}`);
    expect(parsed?.sequence).toBe(12);
    expect(parsed?.update.update_id).toBe("u");
    expect(parseSseBlock(": heartbeat")).toBeNull();
  });
});
