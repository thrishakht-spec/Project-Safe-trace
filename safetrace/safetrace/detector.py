"""Best-effort local sensitive-value detection."""
import math, re, ipaddress
from dataclasses import dataclass

@dataclass(frozen=True)
class Match:
    start: int
    end: int
    category: str
    value: str

PATTERNS = [
    ("AUTH_TOKEN", re.compile(r"(?i)(?<=\bBearer\s)[A-Za-z0-9._~+/=-]{8,}")),
    ("AUTH_TOKEN", re.compile(r"(?i)(?<=\bBasic\s)[A-Za-z0-9+/=]{8,}")),
    ("API_KEY", re.compile(r"\b(?:sk_live|sk_test|ghp_|github_pat_|AKIA)[A-Za-z0-9_\-]{8,}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("DB_CREDENTIAL", re.compile(r"(?i)(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s:/]+:[^\s@]+@[^\s]+")),
    ("ASSIGNMENT_SECRET", re.compile(r"(?i)\b(password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token)\s*[:=]\s*(['\"]?)([^\s,;\"']{4,})\2")),
]

def shannon_entropy(value: str) -> float:
    if not value: return 0.0
    n=len(value)
    return -sum((value.count(ch)/n)*math.log2(value.count(ch)/n) for ch in set(value))

def _valid_ipv4(value):
    try: ipaddress.IPv4Address(value); return True
    except ValueError: return False

def detect_sensitive(text: str, entropy_threshold: float=3.7):
    matches=[]
    for category, pattern in PATTERNS:
        for m in pattern.finditer(text):
            if category == "ASSIGNMENT_SECRET":
                value=m.group(3); start=m.start(3); end=m.end(3)
                if value.lower() in {"none","null","true","false","changeme","example","placeholder"}: continue
            elif category == "DB_CREDENTIAL":
                value=m.group(0); start=m.start(); end=m.end()
            else:
                value=m.group(0); start=m.start(); end=m.end()
            if category == "IP_ADDRESS" and not _valid_ipv4(value): continue
            matches.append(Match(start,end,category,value))
    # Entropy heuristic: only long token-like strings with mixed character classes; avoid identifiers/paths.
    token_re=re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9])")
    for m in token_re.finditer(text):
        v=m.group(0)
        classes=sum(bool(re.search(p,v)) for p in (r"[a-z]",r"[A-Z]",r"\d",r"[_+/=-]"))
        if shannon_entropy(v)>=entropy_threshold and classes>=3:
            matches.append(Match(m.start(),m.end(),"HIGH_ENTROPY",v))
    # Username in common home paths: replace only the username component.
    for m in re.finditer(r"(?:(?<=/home/)|(?<=/Users/))([A-Za-z0-9._-]+)", text):
        matches.append(Match(m.start(1),m.end(1),"USERNAME",m.group(1)))
    # Resolve overlaps by preferring the longest match, then restore source order.
    matches.sort(key=lambda x:(x.start,-(x.end-x.start)))
    chosen=[]
    for item in matches:
        if not chosen or item.start >= chosen[-1].end:
            chosen.append(item)
        elif item.end > chosen[-1].end and item.start == chosen[-1].start:
            chosen[-1]=item
    return chosen
