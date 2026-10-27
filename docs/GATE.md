# Model-access gate

Nothing about Meta model names, endpoints, request formats, authentication, credits, or hackathon model rules is assumed. Each item stays **unconfirmed** until the project owner supplies evidence (documentation excerpts, links, rule text), which is recorded here verbatim with its source and date.

Until an item is confirmed, everything else is built and tested against `internal/llm/scripted`, and every run records which implementation it used. No other provider's model is used without written approval recorded in this file.

| # | Item | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Which Meta models are available, by exact model ID, for the planner and for the processor | **Unconfirmed** | None received |
| 2 | API documentation: endpoint, request and response format, structured-output support, authentication, rate limits | **Unconfirmed** | None received |
| 3 | Whether the hackathon rules require Meta models for every model call, including the C0 baseline | **Unconfirmed** | None received |
| 4 | Credit budget, against about 660 evaluation runs (33 fixtures × 4 configurations × 5 trials) of three to four model calls each, so roughly 2,000 to 2,650 calls | **Unconfirmed** | None received |

## Questions for the project owner

1. Which Meta models can we call, by exact model ID? Is there a hosted model suitable for the planner (JSON plan output) and an open-weight model for the processor (typed extraction)?
2. For each model: the endpoint URL, the request and response JSON format, whether it supports JSON-schema-constrained or JSON-mode output, how to authenticate (header name, key format), and the rate limits. Links to the provider's documentation are enough.
3. Do the hackathon rules require Meta models for every model call, including the C0 baseline? Please paste the rule text.
4. What credit or token budget do we have? The full evaluation needs about 660 runs of three to four calls each.

## Fallbacks (from the specification)

- If no hosted planner model is available by the end of Phase 2, use the Meta open-weight model for both roles.
- If no Meta model is available by the end of Phase 4, deliver deterministic evidence only (Experiments 1, 3, and 4) and state that plainly in the README.
- Never substitute a non-Meta model if the rules forbid it.

## Status log

| Date | Change |
| --- | --- |
| 2026-10-27 | Gate created; all four items unconfirmed; questions sent to the project owner. Model adapters are blocked on items 1 and 2. |
