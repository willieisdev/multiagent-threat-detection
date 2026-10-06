"""LangGraph wiring: gap analysis -> write -> guardrail -> test -> fix loop -> report."""
import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from .guardrails import check_rule
from .models import Rule


class State(TypedDict, total=False):
    queue: list[dict]
    gaps: list[dict]
    current: dict
    rule: dict
    attempts: int
    feedback: dict
    report: dict
    results: Annotated[list, operator.add]
    summary: dict


def build_graph(model, siem, attack, existing_rules, tracer, max_fix=4, min_precision=1.0,
                min_recall=0.8, max_gaps=4, finalize=None):
    def ctx_for(tid):
        return {"positives": siem.pool("dev", "malicious", tid), "negatives": siem.pool("dev", "benign")}

    def gap_analyst(state):
        cov = siem.coverage(existing_rules, "dev")
        gaps = [
            {**attack.lookup(t), "coverage": c} for t, c in cov.items() if c < 0.5
        ]
        gaps.sort(key=lambda g: (-g["severity"], g["coverage"], g["id"]))
        gaps = gaps[:max_gaps]
        return {"gaps": gaps, "queue": list(gaps), "results": []}

    def next_gap(state):
        q = list(state["queue"])
        if not q:
            return {"current": None}
        return {"current": q[0], "queue": q[1:], "attempts": 0, "feedback": {}}

    def rule_writer(state):
        rule = model.draft_rule(state["current"])
        return {"rule": rule.model_dump()}

    def guardrail(state):
        errs = check_rule(Rule(**state["rule"]))
        return {"feedback": {"kind": "guardrail", "errors": errs} if errs else {}}

    def tester(state):
        rule = Rule(**state["rule"])
        rep = siem.evaluate(rule, state["current"]["id"], "dev")
        rep["passed"] = rep["precision"] >= min_precision and rep["recall"] >= min_recall
        return {"report": rep, "feedback": {"kind": "test", "report": rep}}

    def rule_fixer(state):
        rule = Rule(**state["rule"])
        fixed = model.revise_rule(rule, state["feedback"], ctx_for(state["current"]["id"]))
        return {"rule": fixed.model_dump(), "attempts": state["attempts"] + 1}

    def accept(state):
        r = {"technique": state["current"]["id"], "status": "accepted",
             "attempts": state["attempts"], "rule": state["rule"], "dev": state["report"]}
        return {"results": [r]}

    def reject(state):
        r = {"technique": state["current"]["id"], "status": "needs_human_review",
             "attempts": state["attempts"], "rule": state["rule"], "dev": state.get("report", {})}
        return {"results": [r]}

    def reporter(state):
        return {"summary": finalize(state) if finalize else {}}

    def after_next(state):
        return "rule_writer" if state.get("current") else "reporter"

    def after_guard(state):
        if not state["feedback"]:
            return "tester"
        return "rule_fixer" if state["attempts"] < max_fix else "reject"

    def after_test(state):
        if state["report"]["passed"]:
            return "accept"
        return "rule_fixer" if state["attempts"] < max_fix else "reject"

    def after_fix(state):
        return "guardrail"

    g = StateGraph(State)
    nodes = dict(gap_analyst=gap_analyst, next_gap=next_gap, rule_writer=rule_writer,
                 guardrail=guardrail, tester=tester, rule_fixer=rule_fixer,
                 accept=accept, reject=reject, reporter=reporter)
    for n, f in nodes.items():
        g.add_node(n, tracer.wrap(n, f))
    g.add_edge(START, "gap_analyst")
    g.add_edge("gap_analyst", "next_gap")
    g.add_conditional_edges("next_gap", after_next, ["rule_writer", "reporter"])
    g.add_edge("rule_writer", "guardrail")
    g.add_conditional_edges("guardrail", after_guard, ["tester", "rule_fixer", "reject"])
    g.add_conditional_edges("tester", after_test, ["accept", "rule_fixer", "reject"])
    g.add_edge("rule_fixer", "guardrail")
    g.add_edge("accept", "next_gap")
    g.add_edge("reject", "next_gap")
    g.add_edge("reporter", END)
    return g.compile()
