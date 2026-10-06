"""Model backends for the rule writer and fixer agents.

OfflineModel needs no API key. It drafts a broad rule from the ATT&CK entry and
repairs it by learning from the labelled dev events (greedy set cover over
command line tokens). It exists so the full graph runs anywhere, deterministically.

GeminiModel uses the google-genai SDK with a JSON response schema for structured output.
It was not exercised in the sandbox this repo was built in (no API key there).
"""
import json
import os
from dotenv import load_dotenv
load_dotenv()
import re
from typing import Literal

from pydantic import BaseModel

from .models import FIELDS, Condition, Rule
from .siem import norm_cmd, rule_matches


def _tokens(cmd: str) -> set[str]:
    n = norm_cmd(cmd)
    whole = {f" {t} " for t in n.split() if len(t) >= 2}
    parts = {s for s in re.split(r"[\\/\s,]+", n) if len(s) >= 4}
    return whole | parts


def greedy_cover(targets: list[dict], forbidden: list[dict]) -> tuple[list[str], int]:
    """Pick command line substrings that match the targets and none of the forbidden
    events. Returns (chosen substrings, number of targets left uncovered)."""
    ttext = [norm_cmd(e["CommandLine"]) for e in targets]
    ftext = [norm_cmd(e["CommandLine"]) for e in forbidden]
    cands = set().union(*[_tokens(e["CommandLine"]) for e in targets]) if targets else set()
    cover = {}
    for c in cands:
        if any(c in t for t in ftext):
            continue
        cover[c] = {i for i, t in enumerate(ttext) if c in t}
    uncovered, chosen = set(range(len(targets))), []
    while uncovered and cover:
        best = max(cover, key=lambda c: (len(cover[c] & uncovered), len(c), c))
        if not cover[best] & uncovered:
            break
        chosen.append(best)
        uncovered -= cover[best]
    return sorted(chosen), len(uncovered)


class OfflineModel:
    name = "offline-heuristic"

    def __init__(self, inject_fault: bool = True):
        self.inject_fault = inject_fault

    def draft_rule(self, tech: dict) -> Rule:
        if tech["key_binary"]:
            field, op, val = "Image", "endswith", tech["key_binary"]
        else:
            field, op, val = "CommandLine", "contains_any", [tech["keyword"]]
        if self.inject_fault and tech["id"] == "T1070.001":
            field = "ProcessName"  # seeded fault so the guardrail route is exercised
        return Rule(
            title=f"Possible {tech['name']}", technique=tech["id"],
            description=f"{tech['tactic']}: {tech['name']}",
            selection=[Condition(field=field, op=op, value=val)],
            level="high" if tech["severity"] >= 4 else "medium",
        )

    def revise_rule(self, rule: Rule, fb: dict, ctx: dict) -> Rule:
        rule = rule.model_copy(deep=True)
        if fb["kind"] == "guardrail":
            for c in rule.selection + rule.filters:
                if c.field not in FIELDS:
                    c.field = "Image"
            return rule
        pos, neg = ctx["positives"], ctx["negatives"]
        hit = [e for e in pos if rule_matches(rule, e)]
        fps = [e for e in neg if rule_matches(rule, e)]
        if fps:
            narrow, n_left = greedy_cover(hit, fps)       # require attacker-only tokens
            exclude, x_left = greedy_cover(fps, hit)      # or exclude the benign ones
            can_narrow, can_exclude = n_left == 0 and narrow, x_left == 0 and exclude
            if can_narrow and (not can_exclude or len(narrow) < len(exclude)):
                rule.selection.append(Condition(field="CommandLine", op="contains_any", value=narrow))
                return rule
            if can_exclude:
                rule.filters.append(Condition(field="CommandLine", op="contains_any", value=exclude))
                return rule
        fns = [e for e in pos if not rule_matches(rule, e)]
        if fns:
            cond = next((c for c in rule.selection if c.field == "CommandLine" and c.op == "contains_any"), None)
            extra, _ = greedy_cover(fns, neg)
            if cond and extra:
                cond.value = list(cond.value) + [v for v in extra if v not in cond.value]
        return rule


class _GCondition(BaseModel):
    field: str
    op: Literal["equals", "contains", "endswith", "contains_any", "regex"]
    value: list[str]


class _GRule(BaseModel):
    """Flat schema sent to Gemini. Same as Rule, but every value is a list and
    nothing has a default, which keeps the JSON schema simple for the API."""

    title: str
    technique: str
    description: str
    selection: list[_GCondition]
    filters: list[_GCondition]
    level: Literal["low", "medium", "high", "critical"]


def _to_rule(g: _GRule) -> Rule:
    def conv(c: _GCondition) -> Condition:
        v = c.value if (c.op == "contains_any" or len(c.value) != 1) else c.value[0]
        return Condition(field=c.field, op=c.op, value=v)

    return Rule(title=g.title, technique=g.technique, description=g.description,
                selection=[conv(c) for c in g.selection], filters=[conv(c) for c in g.filters],
                level=g.level)


class GeminiModel:
    SYSTEM = (
        "You are a detection engineer. Write or repair a Sigma-like rule for Windows process "
        "creation events with fields Image, CommandLine, ParentImage, User. Selection conditions "
        "are ANDed, filters exclude. For contains_any, matching is a case-insensitive substring "
        "test on the command line with quotes removed. Prefer specific attacker behaviour over "
        "broad matches, and avoid overfitting to the examples. Use selection for what must be "
        "present and filters only when needed. Leave filters empty if unused."
    )

    def __init__(self, model: str | None = None):
        import httpx
        from dotenv import load_dotenv
        from google import genai
        from google.genai import types

        load_dotenv()

        # Force fresh TLS connections (prevents Windows SSL UNEXPECTED_EOF drops)
        http_client = httpx.Client(
            timeout=60.0,
            limits=httpx.Limits(max_keepalive_connections=0, max_connections=10),
        )

        self.client = genai.Client(
            http_options=types.HttpOptions(httpx_client=http_client)
        )
        self.model = model or os.getenv("DEMO_MODEL", "gemini-2.5-flash")
        self.name = f"gemini:{self.model}"

    def _call(self, user: str) -> Rule:
        import time
        from google.genai import types

        for attempt in range(4):
            try:
                resp = self.client.models.generate_content(
                    model=self.model,
                    contents=user,
                    config=types.GenerateContentConfig(
                        system_instruction=self.SYSTEM,
                        response_mime_type="application/json",
                        response_schema=_GRule,
                        temperature=0.2,
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(
                            disable=True
                        ),
                    ),
                )
                parsed = (
                    resp.parsed
                    if isinstance(resp.parsed, _GRule)
                    else _GRule.model_validate_json(resp.text)
                )
                return _to_rule(parsed)
            except Exception as e:
                if attempt == 3:
                    raise
                print(f"  [network retry {attempt + 1}/3 after {type(e).__name__}]")
                time.sleep(2 ** attempt)

    def draft_rule(self, tech: dict) -> Rule:
        return self._call(f"Write a first detection rule for this technique:\n{json.dumps(tech)}")

    def revise_rule(self, rule: Rule, fb: dict, ctx: dict) -> Rule:
        if fb["kind"] == "guardrail":
            body = "Static checks failed:\n" + "\n".join(fb["errors"])
        else:
            r = fb["report"]
            body = (
                f"Test results on dev data: precision {r['precision']}, recall {r['recall']}.\n"
                f"False positives (benign, matched): {r['fp_examples']}\n"
                f"Missed attacks: {r['fn_examples']}"
            )
        return self._call(f"Current rule:\n{rule.model_dump_json()}\n\n{body}\n\nReturn an improved rule.")
