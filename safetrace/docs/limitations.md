# Security limitations

- Detection is heuristic; unknown formats, encoded secrets, split secrets, and context-specific identifiers may be missed.
- Entropy heuristics can create false positives and false negatives.
- Canary score measures only the canaries and matching rule used in that run; it is not a guarantee of zero leakage.
- Username path detection covers common `/home/<name>` and `/Users/<name>` patterns, not every operating system or path format.
- The deterministic benchmark dataset is synthetic and small; results are engineering checks, not real-world diagnostic accuracy.
- Ollama is optional. AI output can be wrong. The app only passes sanitized text through its AI button, but users should inspect the result before sharing.
- No software can promise that every secret has been removed. Review output before external sharing.
