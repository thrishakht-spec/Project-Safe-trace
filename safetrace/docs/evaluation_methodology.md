# Evaluation methodology

## Canary test

The canary runner inserts unique synthetic secrets in `password=` assignments. A canary counts as leaked only if its complete original value is present in sanitized output. Leak rate = leaked full canaries / injected canaries × 100. Privacy score = 100 − leak rate. This narrow test does not measure partial fragments, unknown secret types, or all possible attack paths.

## Utility benchmark

The bundled cases are synthetic fixtures. A simple deterministic classifier identifies a broad error category from diagnostic phrases and compares it with the reference category. Accuracy = correct category classifications / cases × 100. This is useful as a repeatable smoke benchmark but is not equivalent to expert judgement or LLM diagnosis quality. The naive baseline uses the same detector and replaces matches with `[REDACTED]`.

For a defensible research result, replace/expand fixtures with 30–50 verified and licensed public cases, document manual root-cause review, run an LLM with the same prompt/model/settings for all conditions, and independently review outputs. Report the exact dataset size and confidence/limitations.
