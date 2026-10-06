"""Final evaluation on held-out events plus the markdown report."""
import json
from pathlib import Path

import yaml

from .models import Rule
from .siem import rule_matches


def finalize(state, siem, existing_rules, model_name, out_dir: Path):
    out_dir = Path(out_dir)
    (out_dir / "rules").mkdir(parents=True, exist_ok=True)
    new_rules = []
    rows = []
    for r in state["results"]:
        rule = Rule(**r["rule"])
        tid = r["technique"]
        hold = siem.evaluate(rule, tid, "holdout")
        rows.append({"technique": tid, "status": r["status"], "attempts": r["attempts"],
                     "dev": r["dev"], "holdout": hold})
        if r["status"] == "accepted":
            new_rules.append(rule)
            (out_dir / "rules" / f"{tid}.yaml").write_text(
                yaml.safe_dump(rule.model_dump(), sort_keys=False, width=100))
    allr = existing_rules + new_rules
    summary = {
        "model": model_name,
        "gaps_found": [g["id"] for g in state["gaps"]],
        "coverage_dev_before": siem.coverage(existing_rules, "dev"),
        "coverage_dev_after": siem.coverage(allr, "dev"),
        "coverage_holdout_before": siem.coverage(existing_rules, "holdout"),
        "coverage_holdout_after": siem.coverage(allr, "holdout"),
        "benign_holdout_alerts_new_rules": sum(
            any(rule_matches(r, e) for r in new_rules)
            for e in siem.pool("holdout", "benign")),
        "rules": rows,
    }
    (out_dir / "metrics.json").write_text(json.dumps(summary, indent=2))
    (out_dir / "report.md").write_text(render_report(summary))
    return summary


def render_report(s) -> str:
    L = ["# Detection gap run report", "", f"Model backend: {s['model']}", "",
         "## Coverage of malicious events (share detected)", "",
         "| Technique | Dev before | Dev after | Holdout before | Holdout after |", "|---|---|---|---|---|"]
    for t in s["coverage_dev_before"]:
        L.append(f"| {t} | {s['coverage_dev_before'][t]:.0%} | {s['coverage_dev_after'][t]:.0%} | "
                 f"{s['coverage_holdout_before'].get(t, 0):.0%} | {s['coverage_holdout_after'].get(t, 0):.0%} |")
    L += ["", "## New rules", "",
          "| Technique | Status | Fix rounds | Dev P / R | Holdout P / R | Holdout FP |", "|---|---|---|---|---|---|"]
    for r in s["rules"]:
        d, h = r["dev"], r["holdout"]
        L.append(f"| {r['technique']} | {r['status']} | {r['attempts']} | {d.get('precision')} / {d.get('recall')} "
                 f"| {h['precision']} / {h['recall']} | {h['fp']} |")
    L += ["", f"Benign holdout events alerted on by the new rules: {s['benign_holdout_alerts_new_rules']}", ""]
    fps = [(r["technique"], x) for r in s["rules"] for x in r["holdout"]["fp_examples"]]
    fns = [(r["technique"], x) for r in s["rules"] for x in r["holdout"]["fn_examples"]]
    if fps or fns:
        L += ["## Holdout errors (what the dev data did not teach the rule)", ""]
        L += [f"- false positive for {t}: `{x}`" for t, x in fps]
        L += [f"- missed attack for {t}: `{x}`" for t, x in fns]
        L.append("")
    return "\n".join(L)
