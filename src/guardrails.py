"""Static checks run on every drafted rule before it touches the SIEM."""
import re

from .models import FIELDS, Rule


def check_rule(rule: Rule) -> list[str]:
    errs = []
    if not rule.selection:
        errs.append("rule has no selection conditions")
    conds = rule.selection + rule.filters
    if len(conds) > 10:
        errs.append("too many conditions (max 10)")
    for c in conds:
        if c.field not in FIELDS:
            errs.append(f"unknown field '{c.field}', allowed: {', '.join(FIELDS)}")
        if c.op == "contains_any" and not isinstance(c.value, list):
            errs.append("contains_any needs a list of values")
        vals = c.value if isinstance(c.value, list) else [c.value]
        for v in vals:
            if not v.strip():
                errs.append("empty match value")
            if c.op == "regex":
                if v.strip() in {".*", ".+"}:
                    errs.append("wildcard regex would match everything")
                try:
                    re.compile(v)
                except re.error as exc:
                    errs.append(f"invalid regex: {exc}")
    if rule.selection and not any(c.field in ("Image", "CommandLine") for c in rule.selection):
        errs.append("selection must reference Image or CommandLine")
    return errs
