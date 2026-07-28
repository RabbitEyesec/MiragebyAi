# Failure recovery runbook

The 13 canonical scenarios are in `mirage_common.resilience.SCENARIOS`. Each
record states preconditions, trigger, detection, alert, safe state, data
behavior, recovery, residual risk, and the exact controlled-lab command.

```sh
make test-failure
./scripts/run-failure-scenario FAIL-01
```

Local execution is a deterministic safety/replay oracle. Scenarios that need a
real Spider, controller, or credential revocation return `NOT_RUN` and name the
lab command. A Profile B operator must capture trigger time, alert time, missing
and duplicate IDs, collection gaps, recovery time, and post-recovery health.

Do not recover by deleting queues, suppressing evidence gaps, marking an
unverified export verified, or describing an unavailable AI provider as a
successful action. Credential invalidation requires the controlled-lab
confirmation and credential-compromise procedure.
