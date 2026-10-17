import secrets, string
from .sanitizer import Sanitizer

def generate_canaries(count=20):
    alphabet=string.ascii_letters+string.digits
    return [f"canary_{i}_"+''.join(secrets.choice(alphabet) for _ in range(24)) for i in range(1,count+1)]

def run_canary_test(count=20):
    canaries=generate_canaries(count)
    log="\n".join(f"request={i} password={value}" for i,value in enumerate(canaries,1))
    sanitizer=Sanitizer(); result=sanitizer.sanitize(log)
    leaked=[v for v in canaries if v in result.text]  # full original value surviving counts as leak
    detected=sum(1 for v in canaries if v not in result.text)
    leak_rate=(len(leaked)/len(canaries)*100) if canaries else 0.0
    return {"total_canaries":len(canaries),"detected_canaries":detected,"leaked_canaries":len(leaked),"leak_rate":leak_rate,"privacy_score":100-leak_rate,"leaked_categories": ["ASSIGNMENT_SECRET"] if leaked else []}
