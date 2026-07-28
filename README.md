# Mirage

A controlled cyber-range and deception platform. Watches a simulated employee
Windows endpoint; when a detection fires, an investigation case opens and a
supported connection is brokered into an isolated Windows sandbox that mirrors
the employee's machine. A low-noise Spider agent observes everything inside the
sandbox; a policy-constrained AI adapts the environment and feeds tracked bait
artifacts. Everything the intruder does is captured, hashed, and assembled into
an evidence-ready investigation package. Everything happens inside Mirage's own
sandbox — nothing reaches out to the intruder's machine.

The single source of truth for scope and design is
`Mirage_Complete_Engineering_Specification.docx`. Everything else in this repo
implements it.

## Start here

- `docs/runbooks/bootstrap.md` — local dev setup and AWS acceptance prerequisites
- `IMPLEMENTATION_STATUS.md` — what's built, what isn't, right now
- `REQUIREMENTS_TRACEABILITY.md` — every requirement, its evidence, its status
- `ARCHITECTURE_DECISIONS.md` — engineering choices the spec left open
- `SESSION_HANDOFF.md` — exactly where the next work session picks up

## Quick start (local development)

```
cp .env.example .env
cp config/development.example.yaml config/development.yaml
scripts/check-prerequisites
scripts/bootstrap-development
make test
```

See `docs/runbooks/bootstrap.md` for full detail, including what requires a
real AWS account or Windows host versus what runs entirely on a laptop with
Docker.
