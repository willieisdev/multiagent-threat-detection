"""Run the detection gap multi-agent demo.

    python run_demo.py                 # offline model, no API key needed
    python run_demo.py --model gemini     # needs GEMINI_API_KEY
"""
import argparse
from pathlib import Path

import yaml

from src.attack import AttackData
from src.evaluate import finalize
from src.graph import build_graph
from src.llm import GeminiModel, OfflineModel
from src.models import Rule
from src.siem import MockSIEM
from src.tracing import Tracer

ROOT = Path(__file__).parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["offline", "gemini"], default="offline")
    ap.add_argument("--max-fix", type=int, default=4)
    ap.add_argument("--no-fault", action="store_true", help="skip the seeded guardrail fault")
    ap.add_argument("--out", default=str(ROOT / "outputs"))
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    siem = MockSIEM(ROOT / "data/events.jsonl")
    attack = AttackData(ROOT / "data/attack_subset.json")
    existing = [Rule(**r) for r in yaml.safe_load((ROOT / "data/existing_rules.yaml").read_text())]
    model = OfflineModel(inject_fault=not a.no_fault) if a.model == "offline" else GeminiModel()
    tracer = Tracer(out / "trace.jsonl")

    graph = build_graph(model, siem, attack, existing, tracer, max_fix=a.max_fix,
                        finalize=lambda st: finalize(st, siem, existing, model.name, out))
    (out / "graph.mmd").write_text(graph.get_graph().draw_mermaid())
    final = graph.invoke({})
    s = final["summary"]

    print(f"model: {s['model']}   gaps found: {', '.join(s['gaps_found'])}\n")
    print(f"{'technique':<11}{'status':<20}{'fixes':<7}{'dev P/R':<12}{'holdout P/R':<12}")
    for r in s["rules"]:
        d, h = r["dev"], r["holdout"]
        print(f"{r['technique']:<11}{r['status']:<20}{r['attempts']:<7}"
              f"{str(d.get('precision')) + '/' + str(d.get('recall')):<12}{str(h['precision']) + '/' + str(h['recall']):<12}")
    print("\nholdout coverage before:", s["coverage_holdout_before"])
    print("holdout coverage after: ", s["coverage_holdout_after"])
    print(f"\nwrote {out}/report.md, metrics.json, trace.jsonl, graph.mmd, rules/")


if __name__ == "__main__":
    main()
