import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detection_engine.engine import DetectionEngine
from detection_engine.models import Event
from detection_engine.parsers import load_events
from detection_engine.rules import RuleError, _parse_rule, load_rules, matches

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
MITRE = {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"}


def ssh(minute: float, outcome: str, user: str = "ubuntu", ip: str = "203.0.113.45") -> Event:
    return Event(timestamp=T0 + timedelta(minutes=minute), source="linux_auth",
                 event_type="ssh_login", outcome=outcome, user=user, src_ip=ip)


def rule(**overrides):
    data = {"id": "T-1", "title": "test", "severity": "high", "mitre": MITRE,
            "filter": {"event_type": "ssh_login"}, "group_by": ["src_ip"]}
    data.update(overrides)
    return _parse_rule(data, "test")


class FilterTests(unittest.TestCase):
    def test_operators(self):
        e = Event(timestamp=T0, source="aws_cloudtrail", event_type="aws_api", action="PutBucketAcl",
                  details={"request_parameters": {"uri": "http://acs.amazonaws.com/groups/global/AllUsers"},
                           "region": "eu-west-3"})
        self.assertTrue(matches(e, {"action": "PutBucketAcl"}))
        self.assertTrue(matches(e, {"action": ["PutBucketAcl", "PutObjectAcl"]}))
        self.assertTrue(matches(e, {"details.request_parameters": {"contains": "AllUsers"}}))
        self.assertTrue(matches(e, {"details.region": {"regex": r"^eu-"}}))
        self.assertTrue(matches(e, {"user": {"exists": False}}))
        self.assertTrue(matches(e, {"action": {"not_in": ["DeleteTrail"]}}))
        self.assertFalse(matches(e, {"action": "DeleteTrail"}))
        self.assertFalse(matches(e, {"details.missing.deep": "x"}))


class ThresholdTests(unittest.TestCase):
    def test_fires_once_per_burst(self):
        r = rule(type="threshold", filter={"outcome": "failure"}, threshold=5, window_minutes=5)
        events = [ssh(i * 0.5, "failure") for i in range(8)]
        alerts = DetectionEngine([r]).run(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 8)
        self.assertEqual(alerts[0].entity, "src_ip=203.0.113.45")

    def test_events_spread_outside_window_do_not_fire(self):
        r = rule(type="threshold", filter={"outcome": "failure"}, threshold=5, window_minutes=5)
        events = [ssh(i * 2, "failure") for i in range(5)]  # spans 8 minutes
        self.assertEqual(DetectionEngine([r]).run(events), [])

    def test_distinct_counts_unique_values(self):
        r = rule(type="threshold", filter={"outcome": "failure"}, threshold=3, distinct="user",
                 window_minutes=10)
        same_user = [ssh(i, "failure", user="root") for i in range(6)]
        self.assertEqual(DetectionEngine([r]).run(same_user), [])
        spray = [ssh(i, "failure", user=u) for i, u in enumerate(["root", "admin", "test"])]
        self.assertEqual(len(DetectionEngine([r]).run(spray)), 1)

    def test_groups_are_independent(self):
        r = rule(type="threshold", filter={"outcome": "failure"}, threshold=3, window_minutes=5)
        events = [ssh(0, "failure", ip="203.0.113.1"), ssh(1, "failure", ip="203.0.113.2"),
                  ssh(2, "failure", ip="203.0.113.1"), ssh(3, "failure", ip="203.0.113.2")]
        self.assertEqual(DetectionEngine([r]).run(events), [])


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.rule = rule(type="sequence", window_minutes=15,
                         first={"filter": {"outcome": "failure"}, "min_count": 5},
                         then={"filter": {"outcome": "success"}})

    def test_success_after_failures_fires(self):
        events = [ssh(i, "failure") for i in range(6)] + [ssh(7, "success")]
        (alert,) = DetectionEngine([self.rule]).run(events)
        self.assertEqual(alert.event_count, 7)
        self.assertEqual(alert.severity, "high")

    def test_too_few_failures_does_not_fire(self):
        events = [ssh(i, "failure") for i in range(2)] + [ssh(3, "success")]
        self.assertEqual(DetectionEngine([self.rule]).run(events), [])

    def test_failures_outside_window_do_not_count(self):
        events = [ssh(i, "failure") for i in range(5)] + [ssh(40, "success")]
        self.assertEqual(DetectionEngine([self.rule]).run(events), [])


class ImpossibleTravelTests(unittest.TestCase):
    def login(self, minute, ip):
        return Event(timestamp=T0 + timedelta(minutes=minute), source="aws_cloudtrail",
                     event_type="console_login", outcome="success", user="bob", src_ip=ip)

    def setUp(self):
        self.rule = rule(type="impossible_travel", filter={"event_type": "console_login"},
                         group_by=["user"], max_speed_kmh=900)

    def test_paris_to_sao_paulo_in_25_minutes(self):
        events = [self.login(0, "192.0.2.30"), self.login(25, "203.0.113.140")]
        (alert,) = DetectionEngine([self.rule]).run(events)
        self.assertIn("Sao Paulo", alert.description)

    def test_plausible_travel_does_not_fire(self):
        events = [self.login(0, "192.0.2.30"), self.login(60 * 14, "203.0.113.140")]
        self.assertEqual(DetectionEngine([self.rule]).run(events), [])

    def test_unknown_ip_is_ignored(self):
        events = [self.login(0, "192.0.2.30"), self.login(5, "signin.amazonaws.com")]
        self.assertEqual(DetectionEngine([self.rule]).run(events), [])


class RuleLoadingTests(unittest.TestCase):
    def test_shipped_rules_are_valid(self):
        rules = load_rules(ROOT / "rules")
        self.assertGreaterEqual(len(rules), 18)
        for r in rules:
            self.assertRegex(r.technique, r"^T\d{4}(\.\d{3})?$", r.id)

    def test_invalid_rules_are_rejected(self):
        with self.assertRaises(RuleError):
            rule(type="threshold")  # missing threshold and window
        with self.assertRaises(RuleError):
            rule(type="match", severity="urgent")
        with self.assertRaises(RuleError):
            rule(type="nonsense")


class SampleScenarioTests(unittest.TestCase):
    """End-to-end: every shipped rule should fire exactly once on the sample attack."""

    def test_sample_attack_triggers_every_rule(self):
        events = load_events([ROOT / "samples" / "auth.log", ROOT / "samples" / "cloudtrail.jsonl"], year=2026)
        rules = load_rules(ROOT / "rules")
        alerts = DetectionEngine(rules).run(events)
        fired = sorted(a.rule_id for a in alerts)
        self.assertEqual(fired, sorted(r.id for r in rules))

    def test_benign_deploy_login_is_not_flagged_as_bruteforce(self):
        events = load_events([ROOT / "samples" / "auth.log"], year=2026)
        alerts = DetectionEngine(load_rules(ROOT / "rules")).run(events)
        self.assertFalse(any("198.51.100.200" in a.entity for a in alerts))


if __name__ == "__main__":
    unittest.main()
