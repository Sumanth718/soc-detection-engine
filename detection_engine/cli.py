"""Command-line interface.

Examples::

    python -m detection_engine scan samples/auth.log samples/cloudtrail.jsonl
    python -m detection_engine scan /var/log/auth.log --rules rules/ --out reports/
    python -m detection_engine rules --rules rules/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import DetectionEngine
from .geo import GeoResolver
from .models import Alert
from .parsers import load_events
from .report import console_summary, write_json, write_markdown
from .rules import RuleError, load_rules

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


def _cmd_scan(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    geo = GeoResolver.from_csv(args.geo) if args.geo else GeoResolver()
    events = load_events(args.logs, year=args.year)
    alerts = DetectionEngine(rules, geo).run(events)

    print(console_summary(alerts, events))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(alerts, out / "alerts.json")
    write_markdown(alerts, events, out / "report.md")
    print(f"\nWrote {out / 'alerts.json'} and {out / 'report.md'}")

    if args.fail_on:
        threshold = Alert.SEVERITY_ORDER[args.fail_on]
        if any(a.severity_rank >= threshold for a in alerts):
            return 2
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    print(f"{len(rules)} rules loaded from {args.rules}\n")
    for r in rules:
        print(f"{r.id:<10} {r.severity:<8} {r.type:<18} {r.technique:<10} {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detection_engine",
        description="Detect attacker behavior in Linux auth logs and AWS CloudTrail "
                    "using YAML rules mapped to MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run detections against log files")
    scan.add_argument("logs", nargs="+", help="auth.log / secure files or CloudTrail JSON")
    scan.add_argument("--rules", default=str(DEFAULT_RULES), help="rule file or directory")
    scan.add_argument("--out", default="reports", help="output directory (default: reports)")
    scan.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    scan.add_argument("--geo", help="CSV GeoIP table: network,country,city,lat,lon")
    scan.add_argument("--fail-on", choices=list(Alert.SEVERITY_ORDER),
                      help="exit with code 2 if any alert is at or above this severity")
    scan.set_defaults(func=_cmd_scan)

    lst = sub.add_parser("rules", help="list loaded detection rules")
    lst.add_argument("--rules", default=str(DEFAULT_RULES))
    lst.set_defaults(func=_cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
