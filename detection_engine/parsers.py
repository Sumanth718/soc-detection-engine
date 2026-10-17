"""Parsers that turn raw log formats into normalized :class:`Event` objects.

Supported sources:

* Linux ``auth.log`` / ``secure`` (sshd, sudo, useradd, usermod)
* AWS CloudTrail, either as JSON Lines or as a ``{"Records": [...]}`` export
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from .models import Event

# --------------------------------------------------------------------------- #
# Linux auth.log
# --------------------------------------------------------------------------- #

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_SSH_FAILED = re.compile(
    r"Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.:a-fA-F]+) port \d+"
)

_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)

_SSH_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)

_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<command>.+)$"
)

_USERADD = re.compile(r"new user: name=(?P<user>[^,]+),")

_USERMOD_GROUP = re.compile(
    r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"
)

_MONTHS = {
    month: index
    for index, month in enumerate(
        [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ],
        start=1,
    )
}


def parse_auth_log(
    lines: Iterable[str],
    year: int | None = None,
) -> Iterator[Event]:
    """Parse syslog-style authentication logs.

    Syslog lines carry no year, so ``year`` defaults to the current UTC year.
    Lines that are not security-relevant are skipped.
    """
    year = year or datetime.now(timezone.utc).year

    for line in lines:
        line = line.rstrip("\n")
        prefix = _SYSLOG_PREFIX.match(line)

        if not prefix:
            continue

        hh, mm, ss = (
            int(value) for value in prefix["time"].split(":")
        )

        ts = datetime(
            year,
            _MONTHS[prefix["month"]],
            int(prefix["day"]),
            hh,
            mm,
            ss,
            tzinfo=timezone.utc,
        )

        host = prefix["host"]
        proc = prefix["proc"]
        msg = prefix["msg"]

        base = {
            "timestamp": ts,
            "source": "linux_auth",
            "host": host,
            "raw": line,
        }

        if proc == "sshd":
            if m := _SSH_FAILED.search(msg):
                yield Event(
                    **base,
                    event_type="ssh_login",
                    outcome="failure",
                    user=m["user"],
                    src_ip=m["ip"],
                    action="login",
                    details={
                        "method": m["method"],
                        "invalid_user": bool(m["invalid"]),
                    },
                )

            elif m := _SSH_ACCEPTED.search(msg):
                yield Event(
                    **base,
                    event_type="ssh_login",
                    outcome="success",
                    user=m["user"],
                    src_ip=m["ip"],
                    action="login",
                    details={"method": m["method"]},
                )

            elif m := _SSH_INVALID.search(msg):
                yield Event(
                    **base,
                    event_type="ssh_invalid_user",
                    outcome="failure",
                    user=m["user"],
                    src_ip=m["ip"],
                    action="login",
                    details={"invalid_user": True},
                )

        elif proc == "sudo":
            if m := _SUDO.search(msg):
                yield Event(
                    **base,
                    event_type="privilege_escalation",
                    outcome="success",
                    user=m["user"],
                    action="sudo",
                    details={
                        "target_user": m["target"],
                        "command": m["command"].strip(),
                    },
                )

        elif proc == "useradd":
            if m := _USERADD.search(msg):
                yield Event(
                    **base,
                    event_type="account_created",
                    outcome="success",
                    user=m["user"],
                    action="useradd",
                )

        elif proc == "usermod" and (
            m := _USERMOD_GROUP.search(msg)
        ):
            yield Event(
                **base,
                event_type="group_membership_change",
                outcome="success",
                user=m["user"],
                action="usermod",
                details={"group": m["group"]},
            )


# --------------------------------------------------------------------------- #
# AWS CloudTrail
# --------------------------------------------------------------------------- #


def _cloudtrail_user(identity: dict) -> str | None:
    if identity.get("type") == "Root":
        return "root"

    if name := identity.get("userName"):
        return name

    arn = identity.get("arn") or ""
    return arn.rsplit("/", 1)[-1] or None


def _normalize_cloudtrail(record: dict) -> Event:
    identity = record.get("userIdentity", {}) or {}
    name = record.get("eventName", "")

    ts = datetime.fromisoformat(
        record["eventTime"].replace("Z", "+00:00")
    )

    additional = record.get("additionalEventData") or {}
    response = record.get("responseElements") or {}

    if name == "ConsoleLogin":
        event_type = "console_login"
        outcome = (
            "success"
            if response.get("ConsoleLogin") == "Success"
            else "failure"
        )
    else:
        event_type = "aws_api"
        outcome = "failure" if record.get("errorCode") else "success"

    return Event(
        timestamp=ts,
        source="aws_cloudtrail",
        event_type=event_type,
        outcome=outcome,
        user=_cloudtrail_user(identity),
        src_ip=record.get("sourceIPAddress"),
        host=record.get("recipientAccountId"),
        action=name,
        details={
            "event_source": record.get("eventSource"),
            "region": record.get("awsRegion"),
            "identity_type": identity.get("type"),
            "mfa_used": additional.get("MFAUsed"),
            "error_code": record.get("errorCode"),
            "user_agent": record.get("userAgent"),
            "request_parameters": record.get("requestParameters") or {},
        },
        raw=json.dumps(record, separators=(",", ":")),
    )


def parse_cloudtrail(text: str) -> Iterator[Event]:
    """Parse CloudTrail as a ``{"Records": [...]}`` document or JSON Lines."""
    stripped = text.strip()

    if not stripped:
        return

    if stripped.startswith("{") and '"Records"' in stripped[:200]:
        for record in json.loads(stripped).get("Records", []):
            yield _normalize_cloudtrail(record)

        return

    for line in stripped.splitlines():
        line = line.strip()

        if line:
            yield _normalize_cloudtrail(json.loads(line))


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #


def load_events(
    paths: Iterable[str | Path],
    year: int | None = None,
) -> list[Event]:
    """Load and parse every file, choosing a parser from the file content."""
    events: list[Event] = []

    for path in paths:
        path = Path(path)
        text = path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        first = text.lstrip()[:1]

        if first in ("{", "["):
            events.extend(parse_cloudtrail(text))
        else:
            events.extend(
                parse_auth_log(text.splitlines(), year=year)
            )

    events.sort(key=lambda event: event.timestamp)

    return events