"""A tiny stand-in for a SIEM search API plus the rule matching engine."""
import json
import re
from pathlib import Path

from .models import Condition, Rule


def norm_cmd(s: str) -> str:
    """Lowercase, drop quotes, collapse spaces and pad with one space on each side,
    so a value like ' cl ' matches the whole token 'cl' only."""
    s = s.lower().replace('"', " ").replace("'", " ")
    return " " + re.sub(r"\s+", " ", s).strip() + " "


def _field_value(field: str, event: dict) -> str:
    raw = event.get(field, "")
    return norm_cmd(raw) if field == "CommandLine" else raw.lower()


def cond_matches(c: Condition, event: dict) -> bool:
    v = _field_value(c.field, event)
    vals = c.value if isinstance(c.value, list) else [c.value]
    vals = [x.lower() for x in vals]
    if c.op == "equals":
        return any(v == x for x in vals)
    if c.op in ("contains", "contains_any"):
        return any(x in v for x in vals)
    if c.op == "endswith":
        return any(v.endswith(x) for x in vals)
    if c.op == "regex":
        return any(re.search(x, event.get(c.field, ""), re.I) for x in vals)
    return False


def rule_matches(rule: Rule, event: dict) -> bool:
    return all(cond_matches(c, event) for c in rule.selection) and not any(
        cond_matches(f, event) for f in rule.filters
    )


class MockSIEM:
    def __init__(self, path: str | Path):
        self.events = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]

    def pool(self, split=None, label=None, technique=None):
        return [
            e
            for e in self.events
            if (split is None or e["split"] == split)
            and (label is None or e["label"] == label)
            and (technique is None or e["technique"] == technique)
        ]

    def search(self, rule: Rule, split=None):
        return [e for e in self.pool(split) if rule_matches(rule, e)]

    def evaluate(self, rule: Rule, technique: str, split: str) -> dict:
        """Score one rule against labelled events of one split."""
        pos = self.pool(split, "malicious", technique)
        neg = self.pool(split, "benign")
        tp = [e for e in pos if rule_matches(rule, e)]
        fn = [e for e in pos if not rule_matches(rule, e)]
        fp = [e for e in neg if rule_matches(rule, e)]
        precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
        recall = len(tp) / len(pos) if pos else 1.0
        return {
            "split": split, "tp": len(tp), "fn": len(fn), "fp": len(fp),
            "precision": round(precision, 3), "recall": round(recall, 3),
            "fp_examples": [e["CommandLine"] for e in fp][:5],
            "fn_examples": [e["CommandLine"] for e in fn][:5],
        }

    def coverage(self, rules: list[Rule], split: str) -> dict:
        """Share of malicious events per technique that at least one rule detects."""
        out = {}
        techs = sorted({e["technique"] for e in self.pool(split, "malicious")})
        for t in techs:
            pos = self.pool(split, "malicious", t)
            hit = sum(any(rule_matches(r, e) for r in rules) for e in pos)
            out[t] = round(hit / len(pos), 3)
        return out
