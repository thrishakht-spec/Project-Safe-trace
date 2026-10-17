import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safetrace.canary import generate_canaries
vals=generate_canaries(10)
log='\n'.join(f'ERROR request={i} password={v}' for i,v in enumerate(vals,1))
Path('demo_canary_log.txt').write_text(log,encoding='utf-8')
print('Wrote demo_canary_log.txt with synthetic canaries only.')
