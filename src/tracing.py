"""Minimal tracing: one JSON line per node execution.

LangGraph also emits LangSmith traces if you export LANGSMITH_TRACING=true and
LANGSMITH_API_KEY. This local tracer keeps the demo runnable with no accounts.
"""
import json
import time
import uuid
from pathlib import Path


class Tracer:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.write_text("")
        self.run_id = uuid.uuid4().hex[:8]
        self.step = 0

    def wrap(self, name, fn):
        def inner(state):
            t0 = time.perf_counter()
            update = fn(state)
            self.step += 1
            rec = {
                "run": self.run_id, "step": self.step, "node": name,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
                "technique": (state.get("current") or {}).get("id"),
                "update": json.loads(json.dumps(update, default=str))
                if len(json.dumps(update, default=str)) < 1500 else {"keys": list(update)},
            }
            with self.path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            return update
        return inner
