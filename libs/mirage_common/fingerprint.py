"""The fingerprint checklist comparator engine (§6.5, referenced by both
Step 9a's golden-image pipeline and Step 10's live gate before ENGAGING):
"A measurable gate... Baseline is a versioned file with named comparators
... Output is a signed per-row report (expected, observed, comparator,
evidence)."

This module is the framework-agnostic, fully portable COMPARISON logic —
pure functions over data, no OS access — mirroring the same split already
used for every Windows agent in this build (service_logic.py vs.
win_service.py): the comparison rules are real and unit-tested here;
actually OBSERVING a live system's installed software / running processes /
etc. requires a real Windows host and is LAB_VERIFICATION_REQUIRED (Step
9a's pipeline and Step 10's live gate are both consumers of this module,
not owners of it).

Baseline shape: infra/fingerprint/baseline.schema.json (Step 7b).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

MUST = "MUST"
SHOULD = "SHOULD"

# §6.5 scoring rule: "MUST 100%, SHOULD >= 75%."
SHOULD_PASS_THRESHOLD = 0.75


@dataclass(frozen=True)
class CheckResult:
    check_name: str
    comparator: str
    level: str
    expected: object
    observed: object
    passed: bool
    evidence: str


@dataclass(frozen=True)
class FingerprintReport:
    target_id: str
    baseline_version: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def must_checks(self) -> list[CheckResult]:
        return [r for r in self.results if r.level == MUST]

    @property
    def should_checks(self) -> list[CheckResult]:
        return [r for r in self.results if r.level == SHOULD]

    @property
    def all_must_passed(self) -> bool:
        """§6.5: 'MUST 100%.' An empty MUST set trivially passes (vacuous
        truth) — every real baseline in this build has at least one MUST
        check, so this only matters for malformed/partial baselines."""
        return all(r.passed for r in self.must_checks)

    @property
    def should_pass_ratio(self) -> float:
        should = self.should_checks
        if not should:
            return 1.0
        return sum(1 for r in should if r.passed) / len(should)

    @property
    def passed(self) -> bool:
        """§6.5: 'MUST 100%, SHOULD >= 75%.'"""
        return self.all_must_passed and self.should_pass_ratio >= SHOULD_PASS_THRESHOLD


def _compare_exact(expected: dict, observed: dict) -> tuple[bool, str]:
    mismatches = {k: (v, observed.get(k)) for k, v in expected.items() if observed.get(k) != v}
    if mismatches:
        return False, f"mismatched fields: {mismatches}"
    return True, "exact match on all expected fields"


def _compare_baseline_match(expected: dict, observed: dict) -> tuple[bool, str]:
    mismatches = {}
    for k, v in expected.items():
        ev = observed.get(k)
        if isinstance(v, list):
            if set(v) != set(ev or []):
                mismatches[k] = (v, ev)
        elif ev != v:
            mismatches[k] = (v, ev)
    if mismatches:
        return False, f"baseline mismatch: {mismatches}"
    return True, "matches baseline"


def _compare_required_subset(expected: dict, observed: dict) -> tuple[bool, str]:
    required = set(expected.get("required", []))
    installed = set(observed.get("installed", []))
    missing = required - installed
    if missing:
        return False, f"missing required items: {sorted(missing)}"
    return True, f"all {len(required)} required items present"


def _compare_no_file_predates_date(expected: dict, observed: dict) -> tuple[bool, str]:
    hire_date_str = expected.get("fictional_hire_date")
    offenders = observed.get("files_predating_hire_date", [])
    if offenders:
        return False, f"{len(offenders)} file(s) predate the fictional hire date {hire_date_str}: {offenders[:5]}"
    return True, f"no files predate {hire_date_str}"


def _compare_allowed_set_forbidden_patterns(expected: dict, observed: dict) -> tuple[bool, str]:
    """§6.5: 'Immediate failure on any visible Mirage-named process/service' —
    the forbidden-pattern check is the hard gate this comparator enforces;
    the rest of allowed_set is informational context, not independently
    enforced (a legitimate OS process absent from a necessarily-incomplete
    allow-list must not fail this check on its own).

    A process explicitly listed in `expected.allowed` is exempt from the
    forbidden_patterns check even if it superficially matches one — the
    real-world case this handles is exactly MirageSpider and
    MirageEnvironmentController themselves, which the baseline's own `note`
    field calls out as sanctioned exceptions to the Mirage*/Spider* pattern
    (they run under their own real, un-disguised service names per Appendix
    G; the forbidden-pattern rule exists to catch anything ELSE
    Mirage-branded leaking into a scenario, not to forbid Mirage's own
    sanctioned agents from existing)."""
    forbidden_patterns = expected.get("forbidden_patterns", [])
    allowed = set(expected.get("allowed", []))
    running = observed.get("running", [])
    regexes = [re.compile(p.replace("*", ".*")) for p in forbidden_patterns]
    hits = [proc for proc in running if proc not in allowed and any(rx.fullmatch(proc) for rx in regexes)]
    if hits:
        return False, f"forbidden-pattern process(es) visible: {hits}"
    return True, f"no forbidden-pattern process visible among {len(running)} running"


def _compare_range(expected: dict, observed: dict) -> tuple[bool, str]:
    value = observed.get("value")
    lo = expected.get("min") if "min" in expected else expected.get("min_hours")
    hi = expected.get("max") if "max" in expected else expected.get("max_hours")
    if value is None:
        return False, "no observed value"
    ok = (lo is None or value >= lo) and (hi is None or value <= hi)
    return ok, f"value={value} range=[{lo},{hi}]"


_COMPARATORS = {
    "exact": _compare_exact,
    "baseline_match": _compare_baseline_match,
    "required_subset": _compare_required_subset,
    "no_file_predates_date": _compare_no_file_predates_date,
    "allowed_set_forbidden_patterns": _compare_allowed_set_forbidden_patterns,
    "range": _compare_range,
}


def run_fingerprint_check(baseline: dict, observed: dict) -> FingerprintReport:
    """`baseline` matches infra/fingerprint/baseline.schema.json's shape.
    `observed` is {check_name: {...observation-specific fields...}} — one
    entry per baseline check name; a missing observation is treated as a
    hard failure (never silently skipped) for MUST checks, matching §6.5's
    'inconsistent sandbox is worse than none' spirit."""
    results: list[CheckResult] = []
    for check_name, check in baseline["checks"].items():
        comparator_name = check["comparator"]
        expected = check["expected"]
        level = check["level"]
        observed_value = observed.get(check_name)

        if observed_value is None:
            results.append(CheckResult(
                check_name=check_name, comparator=comparator_name, level=level,
                expected=expected, observed=None, passed=False, evidence="no observation collected",
            ))
            continue

        comparator_fn = _COMPARATORS[comparator_name]
        passed, evidence = comparator_fn(expected, observed_value)
        results.append(CheckResult(
            check_name=check_name, comparator=comparator_name, level=level,
            expected=expected, observed=observed_value, passed=passed, evidence=evidence,
        ))

    return FingerprintReport(
        target_id=baseline["target_id"], baseline_version=baseline["baseline_version"], results=results,
    )


def days_since(iso_date: str) -> int:
    """Helper for real observation-collection code (not used by the
    comparator itself, which trusts observed['files_predating_hire_date']
    was already computed correctly) — exposed so a future Windows-side
    observation collector has one canonical way to compute this."""
    return (date.today() - date.fromisoformat(iso_date)).days
