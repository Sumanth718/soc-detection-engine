"""Core data models shared by parsers, the rule engine and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, ClassVar


@dataclass
class Event:
    """A log record normalized into a common schema.

    Every parser converts its raw format into this shape so detection rules
    can be written once and applied to any log source.
    """

    timestamp: datetime
    source: str  # e.g. "linux_auth", "aws_cloudtrail"
    event_type: str  # e.g. "ssh_login", "console_login", "aws_api"
    outcome: str = "unknown"  # "success" | "failure" | "unknown"
    user: str | None = None
    src_ip: str | None = None
    host: str | None = None
    action: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def get(self, path: str) -> Any:
        """Return a field by dotted path, e.g. ``details.mfa_used``."""
        parts = path.split(".")
        value: Any = getattr(self, parts[0], None)
        for part in parts[1:]:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class Alert:
    """A detection produced when a rule matches one or more events."""

    rule_id: str
    title: str
    severity: str
    tactic: str
    technique: str
    technique_name: str
    entity: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    description: str = ""
    response: list[str] = field(default_factory=list)
    evidence: list[Event] = field(default_factory=list)

    SEVERITY_ORDER: ClassVar[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}
    @property
    def severity_rank(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity, 0)

    @property
    def attack_url(self) -> str:
        technique_path = self.technique.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{technique_path}/"

    def to_dict(self, max_evidence: int = 10) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": {
                "tactic": self.tactic,
                "technique": self.technique,
                "name": self.technique_name,
                "url": self.attack_url,
            },
            "entity": self.entity,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "description": self.description,
            "response": self.response,
            "evidence": [e.raw or e.to_dict() for e in self.evidence[:max_evidence]],
        }
