# Frontend explainability

Backend alerts expose an explanation object with two layers:

- `plain`: short human wording, why it was flagged, benign alternatives, and
  a verification step.
- `technical`: feature snapshot, evidence, detector method, model version, and
  safety assertions.

The preview UI continues to support its existing scripted fallback. A future
Explain/SOC mode switch should consume these fields rather than display model
metrics as if they were universal performance claims.
