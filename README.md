# Detection gap agents: a LangGraph demo

A small multi-agent system that finds gaps in threat detection coverage, then writes,
tests and repairs detection rules to close them. It mirrors the architecture in the
job description, with a mock SIEM and a 5 technique slice of MITRE ATT&CK so it runs
anywhere in about a second.

## Run it

    pip install -r requirements.txt
    python data/generate_data.py      # optional, events.jsonl is already included
    python run_demo.py                # offline backend, no API key
    export GEMINI_API_KEY=...
    python run_demo.py --model gemini      # real LLM backend, see below
    pytest

Outputs land in `outputs/`: `report.md`, `metrics.json`, `trace.jsonl`, `graph.mmd`
(Mermaid diagram of the graph) and `rules/*.yaml` (the accepted rules).

## How it works

    gap_analyst -> next_gap -> rule_writer -> guardrail -> tester -> accept
                                   ^             |  fail      | fail
                                   |             v            v
                                   +-------- rule_fixer <-----+   (max 4 rounds, then reject)

- **gap_analyst** runs the existing rules over labelled dev events and flags techniques
  with under 50% detection, ranked by severity.
- **rule_writer** drafts a rule as a Pydantic `Rule` (structured output).
- **guardrail** runs static checks (allowed fields, no wildcard regex, valid regex,
  must reference Image or CommandLine). Failures route to the fixer without touching the SIEM.
- **tester** searches the mock SIEM and scores precision and recall on the dev split.
  Gate: precision 1.0 and recall at least 0.8.
- **rule_fixer** gets the guardrail errors or the false positive and missed attack
  examples and returns a revised rule. After 4 rounds the gap is marked
  `needs_human_review`.
- **reporter** scores accepted rules on a **holdout** split the agents never see.

Tools the agents use: `MockSIEM.search/evaluate` (stands in for a SIEM search API) and
`AttackData.lookup` (stands in for ATT&CK data). Swapping in Splunk, an MCP server or a
threat intel platform means replacing those two classes.

## Model backends

`OfflineModel` is a deterministic stand-in so the whole graph runs without a key. It
drafts a broad rule from the ATT&CK entry and repairs it by greedy set cover over
command line tokens in the dev events. It is not an LLM and is only there to exercise
the graph, routing, guardrails and evaluation.

`GeminiModel` uses the `google-genai` SDK with a JSON response schema (a flattened
Pydantic version of `Rule`, converted back after parsing) so the model returns structured
output. Each fix round sends the guardrail errors or the test results, including false
positive and missed attack examples. It reads `GEMINI_API_KEY` from the environment and
the model name from `DEMO_MODEL` (default `gemini-flash-latest`). This backend has not been
run yet, because the environment this was built in had no API key. Check the model name
against the current Gemini model list and expect to tune the prompts.

One fault is seeded on purpose: the first draft for T1070.001 uses a field that does
not exist (`ProcessName`), so the guardrail route is exercised. Use `--no-fault` to skip it.

## What the demo shows

All four new rules pass the dev gate, and coverage on the holdout split goes from
0 to 33% up to 100% for every technique. But each rule also fires on one or two
benign holdout events (precision 0.6 to 0.67). The fixer removed dev false positives
by excluding the exact benign commands it saw, which is overfitting that the dev gate
cannot see. That is the point of the holdout split, and the obvious next experiments are:
a holdout gate inside the loop, a fixer prompt that prefers attacker behaviour over
exclusion lists, and a larger, noisier event set.

## Tracing and evaluation

`trace.jsonl` has one record per node run (step, node, technique, latency, state update).
LangGraph also reports to LangSmith if you set `LANGSMITH_TRACING=true` and
`LANGSMITH_API_KEY`; Langfuse can be added the same way through a callback handler.

## Layout

    run_demo.py          CLI entry point
    src/graph.py         LangGraph state, nodes, routing
    src/llm.py           OfflineModel and GeminiModel
    src/guardrails.py    static rule checks
    src/siem.py          mock SIEM and rule engine
    src/attack.py        ATT&CK lookup
    src/evaluate.py      holdout evaluation and report
    src/tracing.py       JSONL tracer
    data/                events, ATT&CK slice, existing rules
    tests/test_demo.py
