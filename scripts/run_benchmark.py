import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safetrace.benchmark import run_benchmark
report=run_benchmark()
out=Path('benchmark_report.json'); out.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2)); print(f'Wrote {out.resolve()}')
