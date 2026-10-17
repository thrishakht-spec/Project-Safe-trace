"""Session-scoped consistent pseudonym labels."""
class Pseudonymizer:
    def __init__(self): self._mapping={}; self._counts={}
    def label(self, category, value):
        key=(category,value)
        if key not in self._mapping:
            self._counts[category]=self._counts.get(category,0)+1
            self._mapping[key]=f"{category}_{self._counts[category]}"
        return self._mapping[key]
    def replace(self, text, matches):
        for m in reversed(matches):
            text=text[:m.start]+self.label(m.category,m.value)+text[m.end:]
        return text
