# Architecture

- `detector.py`: regex, contextual assignment parsing, IPv4 validation, entropy heuristic, and home-directory username detection.
- `pseudonymizer.py`: in-memory category/value map; repeated values reuse labels for one sanitizer instance.
- `sanitizer.py`: applies non-overlapping matches from right to left so source offsets remain valid.
- `canary.py`: generates fake values and measures complete-value survival.
- `benchmark.py`: deterministic diagnostic-category benchmark over bundled synthetic fixtures.
- `diagnosis.py`: optional local Ollama HTTP call; the UI passes sanitized text only.
- `app.py`: Streamlit UI and scorecards.

The raw-to-placeholder map is intentionally not exposed or persisted. A new `Sanitizer` instance starts a new pseudonymization session.
