"""Output formats: console summary, JSON alerts and a Markdown incident report."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Alert, Event

_ICONS = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] ", "info": "[INFO]"}


def console_summary(alerts: list[Alert], events: list[Event]) -> str:
    lines = [f"Analyzed {len(events)} events -> {len(alerts)} alerts", ""]
    if not alerts:
        lines.append("No detections. Nothing to triage.")
        return "\n".join(lines)
    width = max(len(a.title) for a in alerts)
    for a in alerts:
        lines.append(f"{_ICONS.get(a.severity, '')} {a.rule_id:<10} {a.title:<{width}}  "
                     f"{a.technique:<10} {a.entity}")
    counts = Counter(a.severity for a in alerts)
    lines += ["", "By severity: " + ", ".join(
        f"{sev}={counts[sev]}" for sev in ("critical", "high", "medium", "low", "info") if counts[sev]
    )]
    return "\n".join(lines)


def write_json(alerts: list[Alert], path: Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "alert_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_markdown(alerts: list[Alert], events: list[Event], path: Path) -> None:
    counts = Counter(a.severity for a in alerts)
    sources = Counter(e.source for e in events)
    tactics = Counter(a.tactic for a in alerts)
    period = (f"{events[0].timestamp:%Y-%m-%d %H:%M} to {events[-1].timestamp:%Y-%m-%d %H:%M} UTC"
              if events else "n/a")

    out = [
        "# Detection Report",
        "",
        f"*Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC*",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Events analyzed | {len(events)} ({', '.join(f'{s}: {n}' for s, n in sources.items())}) |",
        f"| Time range | {period} |",
        f"| Alerts | {len(alerts)} |",
        "| By severity | " + (", ".join(f"{s}: {counts[s]}" for s in
                                     ("critical", "high", "medium", "low", "info") if counts[s])
                              or "none") + " |",
        "",
    ]

    if tactics:
        out += ["## MITRE ATT&CK coverage", "", "| Tactic | Alerts |", "|---|---|"]
        out += [f"| {t} | {n} |" for t, n in tactics.most_common()]
        out.append("")

    out += ["## Alerts", ""]
    if not alerts:
        out.append("No detections.")
    for i, a in enumerate(alerts, start=1):
        out += [
            f"### {i}. [{a.severity.upper()}] {a.title}",
            "",
            f"- **Rule:** `{a.rule_id}`",
            f"- **MITRE ATT&CK:** {a.tactic} / [{a.technique} {a.technique_name}]({a.attack_url})",
            f"- **Entity:** `{a.entity}`",
            f"- **Window:** {a.first_seen:%Y-%m-%d %H:%M:%S} to {a.last_seen:%H:%M:%S} UTC "
            f"({a.event_count} events)",
            "",
        ]
        if a.description:
            out += [a.description, ""]
        if a.response:
            out += ["**Recommended response**", ""]
            out += [f"{n}. {step}" for n, step in enumerate(a.response, start=1)]
            out.append("")
        out += ["<details><summary>Evidence</summary>", "", "```"]
        out += [e.raw for e in a.evidence[:10]]
        if len(a.evidence) > 10:
            out.append(f"... {len(a.evidence) - 10} more events")
        out += ["```", "", "</details>", ""]

    path.write_text("\n".join(out), encoding="utf-8")
