# SafeTrace

**Existing tools hide secrets. SafeTrace measures whether what's left is still useful.**

SafeTrace is a local-first Python/Streamlit MVP that detects common sensitive values in logs, consistently pseudonymizes them, preserves diagnostic structure, runs synthetic canary leak tests, and benchmarks diagnostic-category retention.

> Important: SafeTrace is best-effort, not a guarantee of zero leakage. Inspect sanitized output before sharing. Bundled benchmark cases are synthetic, not public issue traces.

## Features

- Regex/context detection for assignment secrets, bearer/basic tokens, common API key patterns, database URLs, email addresses, valid IPv4 addresses, home-path usernames, and high-entropy strings.
- Consistent labels within one sanitization session (`EMAIL_1`, `API_KEY_1`, etc.).
- Local sanitization by default; no external API required.
- Synthetic canary privacy scorecard.
- Reproducible deterministic benchmark comparing raw, naive redaction, and SafeTrace.
- Optional local Ollama diagnosis that receives sanitized text only through the UI.
- pytest suite.

## Requirements

Python 3.11+ recommended. Internet is needed only to install packages. Ollama is optional.

## Install

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL Streamlit prints, usually `http://localhost:8501`.

## Tests and benchmark

```bash
python -m pytest -q
python scripts/run_benchmark.py
python scripts/generate_demo_data.py
```

The benchmark command writes `benchmark_report.json` in the current project directory. Results are calculated at runtime; do not present synthetic benchmark results as real-world accuracy.

## Optional Ollama

Install and run Ollama locally, pull a model (for example `ollama pull llama3.2`), then use the AI Diagnosis tab. Optionally set `OLLAMA_URL` (default `http://localhost:11434`). The app sends only the sanitized text held in the session to the local Ollama endpoint when the user explicitly clicks Diagnose. Ollama errors do not disable the rest of the app.

## Metrics

- Leak rate (%) = surviving full original canary values / injected canary values × 100.
- Privacy score (%) = 100 − leak rate.
- Diagnosis accuracy (%) = correctly classified root-cause categories / cases × 100.

The bundled diagnosis rubric is deterministic phrase/category matching. It is not human-verified diagnosis and the six included examples are synthetic. Read `docs/evaluation_methodology.md` and `data/DATASET_SOURCES.md` before presenting results.

## Project layout

- `app.py`: Streamlit UI
- `safetrace/`: detector, sanitizer, pseudonymizer, metrics, benchmark, optional diagnosis
- `data/`: synthetic demo and benchmark fixtures
- `tests/`: automated tests
- `docs/`: architecture, methodology, limitations

## Security notes

- Never put production secrets in sample data or source control.
- Do not assume a zero-canary-leak result means zero risk.
- Detection is heuristic and may miss secrets or flag non-secrets.
- Sanitized text should be reviewed before sharing.
- The session pseudonym map is in memory only and is not exported.
