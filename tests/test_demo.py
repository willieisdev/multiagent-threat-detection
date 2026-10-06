from pathlib import Path

import yaml

from src.attack import AttackData
from src.graph import build_graph
from src.guardrails import check_rule
from src.llm import OfflineModel
from src.models import Condition, Rule
from src.siem import MockSIEM, rule_matches
from src.tracing import Tracer

ROOT = Path(__file__).parent.parent


def load():
    siem = MockSIEM(ROOT / "data/events.jsonl")
    attack = AttackData(ROOT / "data/attack_subset.json")
    existing = [Rule(**r) for r in yaml.safe_load((ROOT / "data/existing_rules.yaml").read_text())]
    return siem, attack, existing


def run(tmp_path, **kw):
    siem, attack, existing = load()
    tracer = Tracer(tmp_path / "t.jsonl")
    g = build_graph(OfflineModel(**kw), siem, attack, existing, tracer)
    return g.invoke({}), tracer


def test_guardrail_flags_unknown_field_and_wildcard():
    r = Rule(title="x", technique="T0", selection=[Condition(field="ProcessName", op="regex", value=".*")])
    errs = check_rule(r)
    assert any("unknown field" in e for e in errs)
    assert any("wildcard" in e for e in errs)


def test_engine_filter_excludes():
    r = Rule(title="x", technique="T0",
             selection=[Condition(field="Image", op="endswith", value="a.exe")],
             filters=[Condition(field="CommandLine", op="contains_any", value=[" skip "])])
    assert rule_matches(r, {"Image": r"C:\a.exe", "CommandLine": "a.exe run"})
    assert not rule_matches(r, {"Image": r"C:\a.exe", "CommandLine": "a.exe skip"})


def test_gaps_found_and_existing_covered_technique_skipped(tmp_path):
    final, _ = run(tmp_path)
    ids = [g["id"] for g in final["gaps"]]
    assert "T1059.001" not in ids and "T1003.001" in ids and len(ids) == 4


def test_all_rules_pass_dev_gate(tmp_path):
    final, _ = run(tmp_path)
    assert all(r["status"] == "accepted" for r in final["results"])
    assert all(r["dev"]["precision"] == 1.0 and r["dev"]["recall"] >= 0.8 for r in final["results"])


def test_guardrail_route_taken_when_fault_seeded(tmp_path):
    _, tracer = run(tmp_path)
    nodes = [__import__("json").loads(l)["node"] for l in tracer.path.read_text().splitlines()]
    assert nodes.count("rule_fixer") >= 1 and "reporter" in nodes


def test_no_fault_still_works(tmp_path):
    final, _ = run(tmp_path, inject_fault=False)
    assert len(final["results"]) == 4
