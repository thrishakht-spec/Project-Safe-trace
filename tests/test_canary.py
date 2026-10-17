from safetrace.canary import run_canary_test

def test_canary_report_shape_and_rates():
    r=run_canary_test(5)
    assert r['total_canaries']==5
    assert 0 <= r['leak_rate'] <= 100
    assert r['privacy_score']==100-r['leak_rate']
