import json
import unittest

from detection_engine.parsers import parse_auth_log, parse_cloudtrail


class AuthLogParserTests(unittest.TestCase):
    def parse_one(self, line):
        events = list(parse_auth_log([line], year=2026))
        self.assertEqual(len(events), 1, f"expected one event from: {line}")
        return events[0]

    def test_failed_password_invalid_user(self):
        e = self.parse_one("Oct 14 09:01:17 web01 sshd[2201]: Failed password for invalid user admin "
                           "from 203.0.113.45 port 51001 ssh2")
        self.assertEqual((e.event_type, e.outcome, e.user, e.src_ip), ("ssh_login", "failure", "admin", "203.0.113.45"))
        self.assertTrue(e.details["invalid_user"])
        self.assertEqual(e.timestamp.isoformat(), "2026-10-14T09:01:17+00:00")

    def test_accepted_publickey(self):
        e = self.parse_one("Oct  4 08:02:00 web01 sshd[1201]: Accepted publickey for alice from 192.0.2.10 "
                           "port 50122 ssh2: ED25519 SHA256:abc")
        self.assertEqual((e.outcome, e.user, e.details["method"]), ("success", "alice", "publickey"))
        self.assertEqual(e.timestamp.day, 4)

    def test_sudo_command(self):
        e = self.parse_one("Oct 14 09:07:00 web01 sudo[2310]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; "
                           "USER=root ; COMMAND=/bin/bash")
        self.assertEqual(e.event_type, "privilege_escalation")
        self.assertEqual(e.details, {"target_user": "root", "command": "/bin/bash"})

    def test_useradd_and_usermod(self):
        events = list(parse_auth_log([
            "Oct 14 09:08:00 web01 useradd[2320]: new user: name=sysupdate, UID=1002, GID=1002",
            "Oct 14 09:08:20 web01 usermod[2321]: add 'sysupdate' to group 'sudo'",
        ], year=2026))
        self.assertEqual([e.event_type for e in events], ["account_created", "group_membership_change"])
        self.assertEqual(events[1].details["group"], "sudo")

    def test_irrelevant_and_malformed_lines_are_skipped(self):
        lines = ["Oct 14 08:00:00 web01 CRON[811]: pam_unix(cron:session): session opened for user root",
                 "this is not syslog", ""]
        self.assertEqual(list(parse_auth_log(lines, year=2026)), [])


class CloudTrailParserTests(unittest.TestCase):
    RECORD = {
        "eventTime": "2026-10-14T10:05:00Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "bob"},
        "sourceIPAddress": "203.0.113.140",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }

    def test_console_login_jsonl(self):
        (e,) = parse_cloudtrail(json.dumps(self.RECORD))
        self.assertEqual((e.event_type, e.outcome, e.user), ("console_login", "success", "bob"))
        self.assertEqual(e.details["mfa_used"], "No")

    def test_records_document_and_errors(self):
        denied = dict(self.RECORD, eventName="ListUsers", errorCode="AccessDenied")
        doc = json.dumps({"Records": [self.RECORD, denied]})
        events = list(parse_cloudtrail(doc))
        self.assertEqual(len(events), 2)
        self.assertEqual((events[1].event_type, events[1].outcome), ("aws_api", "failure"))
        self.assertEqual(events[1].details["error_code"], "AccessDenied")

    def test_root_identity(self):
        root = dict(self.RECORD, userIdentity={"type": "Root", "arn": "arn:aws:iam::111122223333:root"})
        (e,) = parse_cloudtrail(json.dumps(root))
        self.assertEqual(e.user, "root")
        self.assertEqual(e.details["identity_type"], "Root")


if __name__ == "__main__":
    unittest.main()
