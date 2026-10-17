from dataclasses import dataclass
from collections import Counter
from .detector import detect_sensitive
from .pseudonymizer import Pseudonymizer

@dataclass
class SanitizationResult:
    text: str
    stats: dict
    detected_categories: list

class Sanitizer:
    def __init__(self): self.pseudonymizer=Pseudonymizer()
    def sanitize(self, text):
        matches=detect_sensitive(text)
        output=self.pseudonymizer.replace(text,matches)
        categories=Counter(m.category for m in matches)
        return SanitizationResult(output, {"replacements":len(matches),"by_category":dict(categories)}, sorted(categories))

def naive_redact(text):
    matches=detect_sensitive(text)
    for m in reversed(matches): text=text[:m.start]+"[REDACTED]"+text[m.end:]
    return text
