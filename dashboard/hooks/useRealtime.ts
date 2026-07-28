"use client";

import { useEffect, useReducer, useRef } from "react";

import {
  initialRealtimeState,
  parseSseBlock,
  realtimeReducer,
} from "@/hooks/realtime";
import { api } from "@/services/api";

export function useRealtime(caseId: string | null) {
  const [state, dispatch] = useReducer(realtimeReducer, initialRealtimeState);
  const lastSequence = useRef(0);

  useEffect(() => {
    lastSequence.current = state.lastSequence;
  }, [state.lastSequence]);

  useEffect(() => {
    if (!caseId) return;
    lastSequence.current = 0;
    const controller = new AbortController();
    let reconnectAttempt = 0;

    async function refresh() {
      dispatch({ type: "MODEL", model: await api.case(caseId!) });
    }

    async function connect() {
      while (!controller.signal.aborted) {
        dispatch({
          type: "STATUS",
          status: reconnectAttempt ? "RECONNECTING" : "CONNECTING",
        });
        try {
          const response = await fetch(
            `/api/mirage/v1/dashboard/stream?case_id=${encodeURIComponent(caseId!)}&last_event_id=${lastSequence.current}`,
            {
              headers: { accept: "text/event-stream" },
              signal: controller.signal,
              cache: "no-store",
            },
          );
          if (!response.ok || !response.body) throw new Error("real-time stream unavailable");
          reconnectAttempt = 0;
          dispatch({ type: "STATUS", status: "CONNECTED" });
          const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
          let buffer = "";
          while (!controller.signal.aborted) {
            const result = await reader.read();
            if (result.done) break;
            buffer += result.value;
            const blocks = buffer.split("\n\n");
            buffer = blocks.pop() ?? "";
            for (const block of blocks) {
              const parsed = parseSseBlock(block);
              if (parsed) dispatch({ type: "UPDATE", ...parsed });
            }
          }
        } catch {
          if (controller.signal.aborted) return;
          reconnectAttempt += 1;
          dispatch({ type: "STATUS", status: "RECONNECTING" });
          await new Promise((resolve) =>
            setTimeout(resolve, Math.min(1000 * 2 ** reconnectAttempt, 15_000)),
          );
        }
      }
    }

    refresh().then(connect).catch(() => dispatch({ type: "STATUS", status: "STALE" }));
    return () => controller.abort();
    // A stream is intentionally restarted only when the case changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  useEffect(() => {
    if (caseId && state.needsRefresh) {
      api.case(caseId).then((model) => dispatch({ type: "MODEL", model })).catch(() => {
        dispatch({ type: "STATUS", status: "STALE" });
      });
    }
  }, [caseId, state.needsRefresh]);

  return state;
}
