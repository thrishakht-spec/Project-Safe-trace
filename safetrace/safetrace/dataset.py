"""Load bundled synthetic cases; public examples must be verified before import."""
import json
from pathlib import Path
DATA_PATH=Path(__file__).resolve().parent.parent/'data'/'benchmark_cases.json'
def load_cases():
    with DATA_PATH.open(encoding='utf-8') as f: data=json.load(f)
    if not isinstance(data,list): raise ValueError('Benchmark dataset must be a JSON list')
    for item in data:
        for field in ('case_id','raw_log','root_cause','keywords','fix','source_url','provenance'):
            if field not in item: raise ValueError(f'Missing field {field}')
    return data
