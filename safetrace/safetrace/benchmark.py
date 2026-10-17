from .dataset import load_cases
from .sanitizer import Sanitizer, naive_redact
from .canary import run_canary_test

def _category_guess(text):
    t=text.lower()
    if 'http 401' in t or 'unauthorized' in t or 'authenticationerror' in t: return 'authentication'
    if 'connectionrefused' in t or 'connection refused' in t or 'errno 111' in t: return 'connection'
    if 'filenotfounderror' in t or 'no such file' in t: return 'missing_file'
    if 'keyerror' in t or 'missing key' in t: return 'missing_key'
    if 'zerodivisionerror' in t or 'division by zero' in t: return 'division_by_zero'
    if 'modulenotfounderror' in t or 'no module named' in t: return 'missing_module'
    return 'unknown'

def run_benchmark():
    cases=load_cases(); methods={'Raw logs':lambda x:x,'Naive redaction':naive_redact,'SafeTrace':lambda x:Sanitizer().sanitize(x).text}
    rows=[]
    for name,transform in methods.items():
        correct=0; total=0; leaked=0; injected=0
        for case in cases:
            source=case['raw_log']; transformed=transform(source)
            guess=_category_guess(transformed)
            correct += int(guess==case['root_cause']); total += 1
            canaries=case.get('canaries',[]); injected += len(canaries)
            leaked += sum(1 for c in canaries if c in transformed)
        leak_rate=(leaked/injected*100) if injected else 0.0
        rows.append({'Method':name,'Privacy score (%)':round(100-leak_rate,2),'Leak rate (%)':round(leak_rate,2),'Diagnosis accuracy (%)':round(correct/total*100,2) if total else 0,'Correct cases':correct,'Sample size':total,'Canaries leaked':leaked,'Canaries injected':injected})
    return {'sample_size':len(cases),'evaluation':'Deterministic category-rule scoring on synthetic fixtures; not human/LLM diagnosis validation.','rows':rows}
