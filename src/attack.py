"""Lookup tool over a small local slice of MITRE ATT&CK."""
import json
from pathlib import Path


class AttackData:
    def __init__(self, path: str | Path):
        self.techniques = {t["id"]: t for t in json.loads(Path(path).read_text())}

    def lookup(self, technique_id: str) -> dict:
        return self.techniques[technique_id]
