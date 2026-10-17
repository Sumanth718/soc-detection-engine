"""Loading, validating and matching YAML detection rules.

A rule file looks like this::

    id: SSH-001
    title: SSH brute force from a single source
    severity: high
    type: threshold
    mitre:
      tactic: Credential Access
      technique: T1110.001
      name: "Brute Force: Password Guessing"
    filter:
      event_type: ssh_login
      outcome: failure
    group_by: [src_ip]
    threshold: 5
    window_minutes: 5

Filter conditions
-----------------
``field: value``             equality
``field: [a, b]``            value is one of the list
``field: {op: value}``       operators: equals, in, not, not_in, contains,
                             regex, exists, gte, lte
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Event

RULE_TYPES = {"match", "threshold", "sequence", "impossible_travel"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str
    tactic: str
    technique: str
    technique_name: str
    filter: dict[str, Any] = field(default_factory=dict)
    group_by: list[str] = field(default_factory=list)
    description: str = ""
    response: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    path: str = ""


# --------------------------------------------------------------------------- #
# Filter matching
# --------------------------------------------------------------------------- #

def _check(value: Any, op: str, expected: Any) -> bool:
    if op == "equals":
        return value == expected
    if op == "in":
        return value in expected
    if op == "not":
        return value != expected
    if op == "not_in":
        return value not in expected
    if op == "contains":
        if isinstance(value, (dict, list)):
            return expected in str(value)
        return value is not None and str(expected).lower() in str(value).lower()
    if op == "regex":
        return value is not None and re.search(expected, str(value)) is not None
    if op == "exists":
        return (value is not None) == bool(expected)
    if op == "gte":
        return value is not None and value >= expected
    if op == "lte":
        return value is not None and value <= expected
    raise RuleError(f"unknown operator '{op}'")


def matches(event: Event, conditions: dict[str, Any] | None) -> bool:
    """Return True when the event satisfies every condition."""
    for path, condition in (conditions or {}).items():
        value = event.get(path)
        if isinstance(condition, list):
            if value not in condition:
                return False
        elif isinstance(condition, dict):
            if not all(_check(value, op, expected) for op, expected in condition.items()):
                return False
        elif value != condition:
            return False
    return True


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_REQUIRED_PARAMS = {
    "match": [],
    "threshold": ["threshold", "window_minutes"],
    "sequence": ["first", "then", "window_minutes"],
    "impossible_travel": ["max_speed_kmh"],
}


def _parse_rule(data: dict[str, Any], source: str) -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{source}: rule must be a mapping")
    for key in ("id", "title", "severity", "type", "mitre"):
        if key not in data:
            raise RuleError(f"{source}: missing required key '{key}'")
    if data["type"] not in RULE_TYPES:
        raise RuleError(f"{source}: unknown type '{data['type']}'")
    if data["severity"] not in SEVERITIES:
        raise RuleError(f"{source}: unknown severity '{data['severity']}'")
    for key in _REQUIRED_PARAMS[data["type"]]:
        if key not in data:
            raise RuleError(f"{source}: '{data['type']}' rules need '{key}'")

    mitre = data["mitre"] or {}
    known = {"id", "title", "severity", "type", "mitre", "filter", "group_by",
             "description", "response", "enabled"}
    return Rule(
        id=str(data["id"]),
        title=data["title"],
        severity=data["severity"],
        type=data["type"],
        tactic=mitre.get("tactic", ""),
        technique=mitre.get("technique", ""),
        technique_name=mitre.get("name", ""),
        filter=data.get("filter") or {},
        group_by=list(data.get("group_by") or []),
        description=(data.get("description") or "").strip(),
        response=list(data.get("response") or []),
        params={k: v for k, v in data.items() if k not in known},
        enabled=bool(data.get("enabled", True)),
        path=source,
    )


def load_rules(path: str | Path) -> list[Rule]:
    """Load every ``*.yml``/``*.yaml`` rule from a file or directory."""
    path = Path(path)
    files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    rules: list[Rule] = []
    seen: set[str] = set()
    for file in files:
        with open(file, encoding="utf-8") as handle:
            for doc in yaml.safe_load_all(handle):
                if doc is None:
                    continue
                rule = _parse_rule(doc, str(file))
                if rule.id in seen:
                    raise RuleError(f"{file}: duplicate rule id '{rule.id}'")
                seen.add(rule.id)
                if rule.enabled:
                    rules.append(rule)
    return rules
