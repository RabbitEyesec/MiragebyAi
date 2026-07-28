import type { DashboardReadModelV1, DashboardRealtimeUpdateV1 } from "@/models";

export interface RealtimeState {
  model: DashboardReadModelV1 | null;
  lastSequence: number;
  seenUpdateIds: ReadonlySet<string>;
  connection: "CONNECTING" | "CONNECTED" | "RECONNECTING" | "STALE";
  needsRefresh: boolean;
}

export type RealtimeAction =
  | { type: "MODEL"; model: DashboardReadModelV1 }
  | { type: "STATUS"; status: RealtimeState["connection"] }
  | { type: "UPDATE"; sequence: number; update: DashboardRealtimeUpdateV1 };

export const initialRealtimeState: RealtimeState = {
  model: null,
  lastSequence: 0,
  seenUpdateIds: new Set(),
  connection: "CONNECTING",
  needsRefresh: false,
};

export function realtimeReducer(
  state: RealtimeState,
  action: RealtimeAction,
): RealtimeState {
  if (action.type === "MODEL") {
    return { ...state, model: action.model, needsRefresh: false };
  }
  if (action.type === "STATUS") {
    return { ...state, connection: action.status };
  }
  if (state.seenUpdateIds.has(action.update.update_id)) return state;
  const seen = new Set(state.seenUpdateIds);
  seen.add(action.update.update_id);
  while (seen.size > 1000) seen.delete(seen.values().next().value as string);
  const sequenceGap =
    state.lastSequence > 0 && action.sequence !== state.lastSequence + 1;
  const fullRefresh = action.update.update_type === "FULL_REFRESH_REQUIRED";
  return {
    ...state,
    lastSequence: Math.max(state.lastSequence, action.sequence),
    seenUpdateIds: seen,
    connection: "CONNECTED",
    needsRefresh: state.needsRefresh || sequenceGap || fullRefresh,
  };
}

export function parseSseBlock(block: string): {
  sequence: number;
  update: DashboardRealtimeUpdateV1;
} | null {
  if (!block.trim() || block.trimStart().startsWith(":")) return null;
  let id: number | null = null;
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("id:")) id = Number.parseInt(line.slice(3).trim(), 10);
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  if (id === null || !Number.isFinite(id) || !data.length) return null;
  return { sequence: id, update: JSON.parse(data.join("\n")) as DashboardRealtimeUpdateV1 };
}
