"""Generate the sample attack scenario in ``samples/``.

The scenario is a fictional company (AWS account 111122223333) on 14 Oct 2026:

* A Linux web server is brute-forced over SSH, the attacker gets in as
  ``ubuntu``, opens a root shell and creates a backdoor admin account.
* In AWS, user ``bob`` has his password stolen. The attacker logs in from
  another continent without MFA, probes permissions, grants himself admin,
  disables CloudTrail and GuardDuty, opens SSH to the world and makes an
  S3 bucket public.

All IP addresses come from documentation ranges (RFC 5737).

Run: python tools/generate_samples.py
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
DAY = datetime(2026, 10, 14, tzinfo=timezone.utc)
ACCOUNT = "111122223333"


def syslog(
    ts: datetime,
    host: str,
    proc: str,
    msg: str,
    pid: int = 1000,
) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} {proc}[{pid}]: {msg}"


def auth_log() -> list[str]:
    t = DAY.replace(hour=8)

    lines = [
        syslog(
            t,
            "web01",
            "CRON",
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            811,
        ),
        syslog(
            t + timedelta(minutes=2),
            "web01",
            "sshd",
            "Accepted publickey for alice from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:k3x",
            1201,
        ),
        syslog(
            t + timedelta(minutes=40),
            "web01",
            "sshd",
            "Failed password for deploy from 198.51.100.200 port 40001 ssh2",
            1290,
        ),
        syslog(
            t + timedelta(minutes=41),
            "web01",
            "sshd",
            "Failed password for deploy from 198.51.100.200 port 40002 ssh2",
            1291,
        ),
        syslog(
            t + timedelta(minutes=42),
            "web01",
            "sshd",
            "Accepted password for deploy from 198.51.100.200 port 40003 ssh2",
            1292,
        ),
    ]

    # Attack: spraying and brute force from 203.0.113.45
    attack = DAY.replace(hour=9, minute=1)

    attempts = [
        ("root", False),
        ("admin", True),
        ("test", True),
        ("oracle", True),
        ("ubuntu", False),
        ("ubuntu", False),
        ("root", False),
        ("ubuntu", False),
        ("postgres", True),
        ("ubuntu", False),
        ("ubuntu", False),
        ("ubuntu", False),
    ]

    for i, (user, invalid) in enumerate(attempts):
        ts = attack + timedelta(seconds=17 * i)
        pid = 2200 + i

        if invalid:
            lines.append(
                syslog(
                    ts,
                    "web01",
                    "sshd",
                    f"Invalid user {user} from 203.0.113.45 port {51000 + i}",
                    pid,
                )
            )

            msg = (
                f"Failed password for invalid user {user} "
                f"from 203.0.113.45 port {51000 + i} ssh2"
            )

            lines.append(syslog(ts, "web01", "sshd", msg, pid))
        else:
            lines.append(
                syslog(
                    ts,
                    "web01",
                    "sshd",
                    f"Failed password for {user} "
                    f"from 203.0.113.45 port {51000 + i} ssh2",
                    pid,
                )
            )

    win = attack + timedelta(minutes=5)

    lines += [
        syslog(
            win,
            "web01",
            "sshd",
            "Accepted password for ubuntu from 203.0.113.45 port 51099 ssh2",
            2299,
        ),
        syslog(
            win + timedelta(minutes=1),
            "web01",
            "sudo",
            "  ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash",
            2310,
        ),
        syslog(
            win + timedelta(minutes=2),
            "web01",
            "useradd",
            "new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate, "
            "shell=/bin/bash, from=/dev/pts/1",
            2320,
        ),
        syslog(
            win + timedelta(minutes=2, seconds=20),
            "web01",
            "usermod",
            "add 'sysupdate' to group 'sudo'",
            2321,
        ),
        syslog(
            win + timedelta(minutes=30),
            "web01",
            "sudo",
            "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
            "COMMAND=/usr/bin/systemctl restart nginx",
            2400,
        ),
        syslog(
            DAY.replace(hour=11, minute=15),
            "web01",
            "sshd",
            "Accepted publickey for root from 192.0.2.20 port 60111 ssh2: RSA SHA256:q9w",
            2500,
        ),
    ]

    return lines


def ct(
    ts: datetime,
    name: str,
    source: str,
    user: str | None,
    ip: str,
    *,
    identity_type: str = "IAMUser",
    error: str | None = None,
    request: dict | None = None,
    response: dict | None = None,
    additional: dict | None = None,
    agent: str = "aws-cli/2.17.0",
) -> dict:
    identity = {"type": identity_type, "accountId": ACCOUNT}

    if identity_type == "Root":
        identity["arn"] = f"arn:aws:iam::{ACCOUNT}:root"
    else:
        identity.update(
            userName=user,
            arn=f"arn:aws:iam::{ACCOUNT}:user/{user}",
        )

    record = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ip,
        "userAgent": agent,
        "requestParameters": request,
        "responseElements": response,
        "recipientAccountId": ACCOUNT,
    }

    if error:
        record["errorCode"] = error
        record["errorMessage"] = (
            "User is not authorized to perform this operation"
        )

    if additional:
        record["additionalEventData"] = additional

    return record


def login(
    ts,
    user,
    ip,
    ok=True,
    mfa="Yes",
    root=False,
):
    return ct(
        ts,
        "ConsoleLogin",
        "signin.amazonaws.com",
        user,
        ip,
        identity_type="Root" if root else "IAMUser",
        response={
            "ConsoleLogin": "Success" if ok else "Failure",
        },
        additional={
            "MFAUsed": mfa,
            "LoginTo": "https://console.aws.amazon.com/",
        },
        agent="Mozilla/5.0",
    )


def cloudtrail() -> list[dict]:
    d = DAY
    attacker = "203.0.113.140"

    records = [
        login(
            d.replace(hour=8, minute=30),
            "alice",
            "192.0.2.10",
        ),
        ct(
            d.replace(hour=8, minute=35),
            "DescribeInstances",
            "ec2.amazonaws.com",
            "alice",
            "192.0.2.10",
        ),
        login(
            d.replace(hour=9, minute=40),
            "bob",
            "192.0.2.30",
            mfa="No",
        ),
        ct(
            d.replace(hour=9, minute=45),
            "ListBuckets",
            "s3.amazonaws.com",
            "bob",
            "192.0.2.30",
        ),
    ]

    # Credential stuffing then successful login from Sao Paulo
    for i in range(4):
        records.append(
            login(
                d.replace(hour=10, minute=i),
                "bob",
                attacker,
                ok=False,
                mfa="No",
            )
        )

    records.append(
        login(
            d.replace(hour=10, minute=5),
            "bob",
            attacker,
            mfa="No",
        )
    )

    # Permission probing
    probes = [
        ("ListUsers", "iam"),
        ("ListRoles", "iam"),
        ("GetAccountAuthorizationDetails", "iam"),
        ("DescribeInstances", "ec2"),
        ("DescribeSecurityGroups", "ec2"),
        ("ListSecrets", "secretsmanager"),
        ("GetSecretValue", "secretsmanager"),
        ("ListKeys", "kms"),
        ("DescribeDBInstances", "rds"),
        ("ListFunctions", "lambda"),
        ("DescribeTrails", "cloudtrail"),
        ("ListDetectors", "guardduty"),
    ]

    for i, (name, svc) in enumerate(probes):
        code = (
            "Client.UnauthorizedOperation"
            if svc == "ec2"
            else "AccessDenied"
        )

        records.append(
            ct(
                d.replace(hour=10, minute=6) + timedelta(seconds=13 * i),
                name,
                f"{svc}.amazonaws.com",
                "bob",
                attacker,
                error=code,
                agent="Boto3/1.35.0",
            )
        )

    t = d.replace(hour=10, minute=12)

    records += [
        ct(
            t,
            "AttachUserPolicy",
            "iam.amazonaws.com",
            "bob",
            attacker,
            request={
                "userName": "bob",
                "policyArn": (
                    "arn:aws:iam::aws:policy/AdministratorAccess"
                ),
            },
        ),
        ct(
            t + timedelta(minutes=1),
            "StopLogging",
            "cloudtrail.amazonaws.com",
            "bob",
            attacker,
            request={
                "name": (
                    f"arn:aws:cloudtrail:eu-west-3:{ACCOUNT}:trail/org-trail"
                ),
            },
        ),
        ct(
            t + timedelta(minutes=2),
            "DeleteDetector",
            "guardduty.amazonaws.com",
            "bob",
            attacker,
            request={
                "detectorId": "12abc34d567e8fa901bc2d34e56789f0",
            },
        ),
        ct(
            t + timedelta(minutes=4),
            "AuthorizeSecurityGroupIngress",
            "ec2.amazonaws.com",
            "bob",
            attacker,
            request={
                "groupId": "sg-0a1b2c3d4e5f67890",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [
                                    {"cidrIp": "0.0.0.0/0"},
                                ],
                            },
                        },
                    ],
                },
            },
        ),
        ct(
            t + timedelta(minutes=6),
            "DeleteBucketPublicAccessBlock",
            "s3.amazonaws.com",
            "bob",
            attacker,
            request={
                "bucketName": "acme-finance-reports",
                "publicAccessBlock": "",
            },
        ),
        ct(
            t + timedelta(minutes=7),
            "PutBucketAcl",
            "s3.amazonaws.com",
            "bob",
            attacker,
            request={
                "bucketName": "acme-finance-reports",
                "AccessControlPolicy": {
                    "AccessControlList": {
                        "Grant": [
                            {
                                "Grantee": {
                                    "URI": (
                                        "http://acs.amazonaws.com/groups/"
                                        "global/AllUsers"
                                    ),
                                },
                                "Permission": "READ",
                            },
                        ],
                    },
                },
            },
        ),
        ct(
            d.replace(hour=12),
            "ConsoleLogin",
            "signin.amazonaws.com",
            None,
            "192.0.2.40",
            identity_type="Root",
            response={"ConsoleLogin": "Success"},
            additional={"MFAUsed": "Yes"},
            agent="Mozilla/5.0",
        ),
        ct(
            d.replace(hour=12, minute=3),
            "StartLogging",
            "cloudtrail.amazonaws.com",
            None,
            "192.0.2.40",
            identity_type="Root",
            request={"name": "org-trail"},
            agent="Mozilla/5.0",
        ),
    ]

    records.sort(key=lambda record: record["eventTime"])

    return records


def main() -> None:
    OUT.mkdir(exist_ok=True)

    (OUT / "auth.log").write_text(
        "\n".join(auth_log()) + "\n",
        encoding="utf-8",
    )

    with open(
        OUT / "cloudtrail.jsonl",
        "w",
        encoding="utf-8",
    ) as handle:
        handle.writelines(
            json.dumps(record) + "\n"
            for record in cloudtrail()
        )

    print(f"Wrote samples to {OUT}")


if __name__ == "__main__":
    main()