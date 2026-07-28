# AI budget

Mirage enforces input/output limits, per-case request limits, and persistent
daily/monthly estimated-cost budgets before provider invocation.

## Operations

Configure `AI_MAX_INPUT_TOKENS`, `AI_MAX_OUTPUT_TOKENS`,
`AI_MAX_REQUESTS_PER_CASE`, `AI_DAILY_BUDGET_GBP`,
`AI_MONTHLY_BUDGET_GBP`, and `AI_USAGE_ALERT_PERCENT`. Review the persisted
`ai_usage` totals and `mirage.ai.estimated_cost` telemetry together; the latter
is operational telemetry, not the accounting source of truth.

At the alert threshold, investigate model mix, retry volume, and case activity.
At exhaustion, keep the deterministic fallback active. Raising a limit requires
an attributed configuration change and a cost-owner approval. Do not delete
usage rows to recover budget.
