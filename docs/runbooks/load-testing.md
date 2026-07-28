# Load testing runbook

The local reduced profile is 250 events/second for four seconds with a
one-second control outage. It proves pacing, replay, zero confirmed loss,
zero effective duplicates, and result-schema behavior; it is not Profile B.

```sh
make test-load-local
./scripts/run-load --profile local --output /tmp/mirage-load-local.json
```

Profile B is 1,000 events/second for five minutes, includes a five-minute
control-plane outage and 15-minute buffering claim, and requires explicit lab
confirmation:

```sh
./scripts/run-load --profile profile-b --confirm-controlled-lab \
  --output load-results.json
```

During the real run capture source-to-Elasticsearch and
sandbox-to-dashboard p50/p95/p99, CPU/RSS, queues, consumer lag, locks, Elastic
bulk failures, loss, duplicates, and recovery. Stop if containment, cost, or
evidence safety limits are exceeded. The in-process Profile B command is only a
paced generator model; final acceptance must measure the deployed components.
