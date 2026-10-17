from safetrace.benchmark import run_benchmark
from safetrace.dataset import load_cases

def test_dataset_has_required_fields():
    assert len(load_cases()) >= 5

def test_benchmark_has_three_methods():
    r=run_benchmark()
    assert r['sample_size'] >= 5
    assert {x['Method'] for x in r['rows']} == {'Raw logs','Naive redaction','SafeTrace'}
    assert all(0 <= x['Diagnosis accuracy (%)'] <= 100 for x in r['rows'])
