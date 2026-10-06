"""Structured outputs shared by all agents."""
from typing import Literal

from pydantic import BaseModel, Field

FIELDS = ("Image", "CommandLine", "ParentImage", "User")
Op = Literal["equals", "contains", "endswith", "contains_any", "regex"]


class Condition(BaseModel):
    field: str
    op: Op
    value: str | list[str]


class Rule(BaseModel):
    """A small Sigma-like detection rule. Selection conditions are ANDed.
    A rule fires when every selection condition matches and no filter matches."""

    title: str
    technique: str = Field(description="MITRE ATT&CK technique id, e.g. T1053.005")
    description: str = ""
    selection: list[Condition]
    filters: list[Condition] = Field(default_factory=list)
    level: Literal["low", "medium", "high", "critical"] = "medium"
