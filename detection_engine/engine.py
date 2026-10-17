"""The detection engine: evaluates rules against a timeline of events."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable

from .geo import GeoResolver, haversine_km
from .models import Alert, Event
from .rules import Rule, matches


def _group_key(event: Event, fields: list[str]) -> tuple:
    return tuple(event.get(f) for f in fields)


def _entity(fields: list[str], key: tuple) -> str:
    if not fields:
        return "global"
    return ", ".join(f"{f}={v}" for f, v in zip(fields, key))


def _make_alert(rule: Rule, entity: str, evidence: list[Event], **extra) -> Alert:
    description = rule.description
    if extra.get("note"):
        description = f"{description}\n\n{extra['note']}".strip()
    return Alert(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        tactic=rule.tactic,
        technique=rule.technique,
        technique_name=rule.technique_name,
        entity=entity,
        first_seen=evidence[0].timestamp,
        last_seen=evidence[-1].timestamp,
        event_count=len(evidence),
        description=description,
        response=rule.response,
        evidence=list(evidence),
    )


class DetectionEngine:
    def __init__(self, rules: Iterable[Rule], geo: GeoResolver | None = None) -> None:
        self.rules = list(rules)
        self.geo = geo or GeoResolver()
        self._handlers = {
            "match": self._run_match,
            "threshold": self._run_threshold,
            "sequence": self._run_sequence,
            "impossible_travel": self._run_impossible_travel,
        }

    def run(self, events: Iterable[Event]) -> list[Alert]:
        timeline = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(self._handlers[rule.type](rule, timeline))
        alerts.sort(key=lambda a: (-a.severity_rank, a.first_seen))
        return alerts

    def _grouped(self, rule: Rule, events: list[Event]) -> dict[tuple, list[Event]]:
        groups: dict[tuple, list[Event]] = defaultdict(list)
        for event in events:
            if matches(event, rule.filter):
                groups[_group_key(event, rule.group_by)].append(event)
        return groups

    # -- match: every matching event, aggregated per entity -------------------
    def _run_match(self, rule: Rule, events: list[Event]) -> list[Alert]:
        return [
            _make_alert(rule, _entity(rule.group_by, key), group)
            for key, group in self._grouped(rule, events).items()
        ]

    # -- threshold: N events (or N distinct values) inside a sliding window ---
    def _run_threshold(self, rule: Rule, events: list[Event]) -> list[Alert]:
        threshold = int(rule.params["threshold"])
        window = timedelta(minutes=float(rule.params["window_minutes"]))
        distinct = rule.params.get("distinct")
        alerts: list[Alert] = []

        for key, group in self._grouped(rule, events).items():
            win: deque[Event] = deque()
            i = 0
            while i < len(group):
                win.append(group[i])
                while win[-1].timestamp - win[0].timestamp > window:
                    win.popleft()
                size = len({e.get(distinct) for e in win}) if distinct else len(win)
                if size >= threshold:
                    # Extend the burst to every event still inside the window,
                    # raise one alert, then restart after it to avoid duplicates.
                    burst = list(win)
                    j = i + 1
                    while j < len(group) and group[j].timestamp - burst[0].timestamp <= window:
                        burst.append(group[j])
                        j += 1
                    note = ""
                    if distinct:
                        values = sorted({str(e.get(distinct)) for e in burst})
                        note = f"Distinct {distinct} values ({len(values)}): {', '.join(values)}"
                    alerts.append(_make_alert(rule, _entity(rule.group_by, key), burst, note=note))
                    win.clear()
                    i = j
                    continue
                i += 1
        return alerts

    # -- sequence: N 'first' events followed by a 'then' event -----------------
    def _run_sequence(self, rule: Rule, events: list[Event]) -> list[Alert]:
        first = rule.params["first"]
        then = rule.params["then"]
        min_count = int(first.get("min_count", 1))
        window = timedelta(minutes=float(rule.params["window_minutes"]))
        alerts: list[Alert] = []

        priors: dict[tuple, deque[Event]] = defaultdict(deque)
        for event in events:
            if not matches(event, rule.filter):
                continue
            key = _group_key(event, rule.group_by)
            history = priors[key]
            while history and event.timestamp - history[0].timestamp > window:
                history.popleft()
            if matches(event, then.get("filter")) and len(history) >= min_count:
                evidence = list(history) + [event]
                note = (f"{len(history)} matching events were followed by "
                        f"'{event.action or event.event_type}' at {event.timestamp.isoformat()}.")
                alerts.append(_make_alert(rule, _entity(rule.group_by, key), evidence, note=note))
                history.clear()
            elif matches(event, first.get("filter")):
                history.append(event)
        return alerts

    # -- impossible travel: two logins too far apart to be physically possible
    def _run_impossible_travel(self, rule: Rule, events: list[Event]) -> list[Alert]:
        max_speed = float(rule.params["max_speed_kmh"])
        min_distance = float(rule.params.get("min_distance_km", 500))
        alerts: list[Alert] = []

        for key, group in self._grouped(rule, events).items():
            previous = None
            for event in group:
                location = self.geo.lookup(event.src_ip)
                if location is None:
                    continue
                if previous is not None:
                    prev_event, prev_loc = previous
                    distance = haversine_km(prev_loc, location)
                    hours = max((event.timestamp - prev_event.timestamp).total_seconds() / 3600,
                                1 / 60)
                    speed = distance / hours
                    if distance >= min_distance and speed > max_speed:
                        note = (f"Login from {prev_loc} ({prev_event.src_ip}) then {location} "
                                f"({event.src_ip}): {distance:,.0f} km in "
                                f"{hours * 60:.0f} min, about {speed:,.0f} km/h.")
                        alerts.append(_make_alert(rule, _entity(rule.group_by, key),
                                                  [prev_event, event], note=note))
                previous = (event, location)
        return alerts
