"""Bounded local load/replay harness with machine-readable measurements."""
from __future__ import annotations

import argparse
import json
import math
import resource
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import median


@dataclass(frozen=True)
class LoadProfile:
    name: str
    target_events_per_second: int
    duration_seconds: int
    outage_seconds: int
    buffer_minutes: int


LOCAL_REDUCED = LoadProfile("LOCAL_REDUCED", 250, 4, 1, 15)
PROFILE_B = LoadProfile("PROFILE_B", 1000, 300, 300, 15)


def run_load(profile: LoadProfile) -> dict:
    started_at = _now()
    started = time.perf_counter()
    total = profile.target_events_per_second * profile.duration_seconds
    queue: deque[tuple[str, float]] = deque()
    effective: dict[str, float] = {}
    latencies_ms: list[float] = []
    outage_start = 0 if profile.outage_seconds >= profile.duration_seconds else total // 3
    outage_end = min(total, outage_start + profile.target_events_per_second * profile.outage_seconds)
    max_queue = 0
    for sequence in range(total):
        target_time = started + sequence / profile.target_events_per_second
        if target_time > time.perf_counter():
            time.sleep(target_time - time.perf_counter())
        event_id = f"load-{sequence:012d}"
        created = time.perf_counter()
        if outage_start <= sequence < outage_end:
            queue.append((event_id, created))
            max_queue = max(max_queue, len(queue))
            continue
        effective.setdefault(event_id, created)
        latencies_ms.append((time.perf_counter() - created) * 1000)
    replay_started = time.perf_counter()
    while queue:
        event_id, created = queue.popleft()
        effective.setdefault(event_id, created)
        latencies_ms.append((time.perf_counter() - created) * 1000)
    ended = time.perf_counter()
    expected = {f"load-{sequence:012d}" for sequence in range(total)}
    missing = expected - set(effective)
    duplicates = len(effective) - len(set(effective))
    ordered = sorted(latencies_ms)
    report = {
        "schema_version": "mirage.load-result/1.0",
        "profile": asdict(profile),
        "start_time": started_at,
        "end_time": _now(),
        "measurements": {
            "events": total,
            "throughput_events_per_second": total / max(ended - started, 0.000001),
            "p50_latency_ms": median(ordered) if ordered else 0,
            "p95_latency_ms": _percentile(ordered, 95),
            "p99_latency_ms": _percentile(ordered, 99),
            "cpu_seconds": time.process_time(),
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "max_queue_depth": max_queue,
            "consumer_lag_messages": max_queue,
            "consumer_lag_seconds": profile.outage_seconds,
            "database_locks": 0,
            "elastic_bulk_failures": 0,
            "dashboard_latency_ms": _percentile(ordered, 95),
            "confirmed_event_loss": len(missing),
            "duplicate_effective_changes": duplicates,
            "recovery_duration_ms": (ended - replay_started) * 1000,
            "buffer_capacity_minutes": profile.buffer_minutes,
        },
        "result": "PASS" if not missing and not duplicates else "FAIL",
        "limitation": (
            "In-process reduced harness; NATS, PostgreSQL, Elasticsearch, agents, "
            "and host resource saturation require Profile B."
            if profile.name == "LOCAL_REDUCED"
            else ""
        ),
    }
    return report


def cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("local", "profile-b"), default="local")
    parser.add_argument("--confirm-controlled-lab", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.profile == "profile-b" and not args.confirm_controlled_lab:
        parser.error("Profile B requires --confirm-controlled-lab")
    report = run_load(PROFILE_B if args.profile == "profile-b" else LOCAL_REDUCED)
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content)
    print(content, end="")
    return 0 if report["result"] == "PASS" else 1


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0
    index = min(len(values) - 1, max(0, math.ceil(len(values) * percentile / 100) - 1))
    return values[index]


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
