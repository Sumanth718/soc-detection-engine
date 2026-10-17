# Detection Report

*Generated 2026-10-16 12:17 UTC*

## Summary

| Metric | Value |
|---|---|
| Events analyzed | 55 (linux_auth: 26, aws_cloudtrail: 29) |
| Time range | 2026-10-14 08:02 to 2026-10-14 12:03 UTC |
| Alerts | 18 |
| By severity | critical: 3, high: 8, medium: 7 |

## MITRE ATT&CK coverage

| Tactic | Alerts |
|---|---|
| Credential Access | 4 |
| Defense Evasion | 3 |
| Persistence | 3 |
| Initial Access | 3 |
| Privilege Escalation | 2 |
| Collection | 2 |
| Discovery | 1 |

## Alerts

### 1. [CRITICAL] Successful SSH login after repeated failures

- **Rule:** `SSH-003`
- **MITRE ATT&CK:** Credential Access / [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Entity:** `src_ip=203.0.113.45`
- **Window:** 2026-10-14 09:01:00 to 09:06:00 UTC (13 events)

A successful SSH login from an IP that failed at least five times in the previous fifteen minutes. The brute force probably worked.

12 matching events were followed by 'login' at 2026-10-14T09:06:00+00:00.

**Recommended response**

1. Treat the host as compromised and open an incident.
2. Kill the active session and lock the account that logged in.
3. Review commands run after the login (shell history, sudo logs, auditd).
4. Look for persistence such as new users, SSH keys or cron jobs.
5. Isolate the host if malicious activity is confirmed.

<details><summary>Evidence</summary>

```
Oct 14 09:01:00 web01 sshd[2200]: Failed password for root from 203.0.113.45 port 51000 ssh2
Oct 14 09:01:17 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2
Oct 14 09:01:34 web01 sshd[2202]: Failed password for invalid user test from 203.0.113.45 port 51002 ssh2
Oct 14 09:01:51 web01 sshd[2203]: Failed password for invalid user oracle from 203.0.113.45 port 51003 ssh2
Oct 14 09:02:08 web01 sshd[2204]: Failed password for ubuntu from 203.0.113.45 port 51004 ssh2
Oct 14 09:02:25 web01 sshd[2205]: Failed password for ubuntu from 203.0.113.45 port 51005 ssh2
Oct 14 09:02:42 web01 sshd[2206]: Failed password for root from 203.0.113.45 port 51006 ssh2
Oct 14 09:02:59 web01 sshd[2207]: Failed password for ubuntu from 203.0.113.45 port 51007 ssh2
Oct 14 09:03:16 web01 sshd[2208]: Failed password for invalid user postgres from 203.0.113.45 port 51008 ssh2
Oct 14 09:03:33 web01 sshd[2209]: Failed password for ubuntu from 203.0.113.45 port 51009 ssh2
... 3 more events
```

</details>

### 2. [CRITICAL] CloudTrail logging stopped or deleted

- **Rule:** `AWS-101`
- **MITRE ATT&CK:** Defense Evasion / [T1562.008 Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:13:00 to 10:13:00 UTC (1 events)

A trail was stopped, deleted or reconfigured. Attackers do this to hide what they do next.

**Recommended response**

1. Re-enable logging immediately (aws cloudtrail start-logging --name <trail>).
2. Investigate every action by this identity since the change.
3. Protect trails with an SCP that denies StopLogging and DeleteTrail.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:13:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"aws-cli/2.17.0","requestParameters":{"name":"arn:aws:cloudtrail:eu-west-3:111122223333:trail/org-trail"},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>

### 3. [CRITICAL] AWS root account used

- **Rule:** `AWS-001`
- **MITRE ATT&CK:** Privilege Escalation / [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- **Entity:** `user=root, src_ip=192.0.2.40`
- **Window:** 2026-10-14 12:00:00 to 12:03:00 UTC (2 events)

The AWS root user performed an action. Root has unrestricted access and should only be used for a handful of account-level tasks.

**Recommended response**

1. Confirm with the account owner that root use was planned.
2. Rotate the root password and verify hardware MFA is enabled.
3. Delete any root access keys.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"Root","accountId":"111122223333","arn":"arn:aws:iam::111122223333:root"},"eventTime":"2026-10-14T12:00:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"192.0.2.40","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"Yes"}}
{"eventVersion":"1.09","userIdentity":{"type":"Root","accountId":"111122223333","arn":"arn:aws:iam::111122223333:root"},"eventTime":"2026-10-14T12:03:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StartLogging","awsRegion":"eu-west-3","sourceIPAddress":"192.0.2.40","userAgent":"Mozilla/5.0","requestParameters":{"name":"org-trail"},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>

### 4. [HIGH] SSH password spraying across many accounts

- **Rule:** `SSH-002`
- **MITRE ATT&CK:** Credential Access / [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- **Entity:** `src_ip=203.0.113.45`
- **Window:** 2026-10-14 09:01:00 to 09:04:07 UTC (12 events)

One source tried four or more different usernames within ten minutes. Spraying tries a few common passwords against many accounts to avoid lockouts.

Distinct user values (6): admin, oracle, postgres, root, test, ubuntu

**Recommended response**

1. List every targeted username and check whether any are valid accounts.
2. Force a password reset for valid accounts that were targeted.
3. Block the source IP and review other hosts for the same activity.

<details><summary>Evidence</summary>

```
Oct 14 09:01:00 web01 sshd[2200]: Failed password for root from 203.0.113.45 port 51000 ssh2
Oct 14 09:01:17 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2
Oct 14 09:01:34 web01 sshd[2202]: Failed password for invalid user test from 203.0.113.45 port 51002 ssh2
Oct 14 09:01:51 web01 sshd[2203]: Failed password for invalid user oracle from 203.0.113.45 port 51003 ssh2
Oct 14 09:02:08 web01 sshd[2204]: Failed password for ubuntu from 203.0.113.45 port 51004 ssh2
Oct 14 09:02:25 web01 sshd[2205]: Failed password for ubuntu from 203.0.113.45 port 51005 ssh2
Oct 14 09:02:42 web01 sshd[2206]: Failed password for root from 203.0.113.45 port 51006 ssh2
Oct 14 09:02:59 web01 sshd[2207]: Failed password for ubuntu from 203.0.113.45 port 51007 ssh2
Oct 14 09:03:16 web01 sshd[2208]: Failed password for invalid user postgres from 203.0.113.45 port 51008 ssh2
Oct 14 09:03:33 web01 sshd[2209]: Failed password for ubuntu from 203.0.113.45 port 51009 ssh2
... 2 more events
```

</details>

### 5. [HIGH] User added to a privileged group

- **Rule:** `LNX-002`
- **MITRE ATT&CK:** Persistence / [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- **Entity:** `host=web01, user=sysupdate`
- **Window:** 2026-10-14 09:08:20 to 09:08:20 UTC (1 events)

An account was added to sudo, wheel, admin or root, which grants administrator rights on the host.

**Recommended response**

1. Confirm the change was approved.
2. Remove the account from the group if it was not.
3. Correlate with LNX-001 in case the account was just created.

<details><summary>Evidence</summary>

```
Oct 14 09:08:20 web01 usermod[2321]: add 'sysupdate' to group 'sudo'
```

</details>

### 6. [HIGH] Impossible travel between console logins

- **Rule:** `AWS-004`
- **MITRE ATT&CK:** Initial Access / [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 09:40:00 to 10:05:00 UTC (2 events)

The same user signed in from two locations that are too far apart for the time between logins. One of the sessions is likely using stolen credentials.

Login from Paris, FR (192.0.2.30) then Sao Paulo, BR (203.0.113.140): 9,402 km in 25 min, about 22,565 km/h.

**Recommended response**

1. Ask the user which login was theirs (VPNs can explain some cases).
2. Revoke active sessions and reset the password and MFA device.
3. Review what the suspicious session did in CloudTrail.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T09:40:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"192.0.2.30","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:05:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
```

</details>

### 7. [HIGH] Administrator policy attached to an IAM user

- **Rule:** `AWS-005`
- **MITRE ATT&CK:** Persistence / [T1098.003 Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:12:00 to 10:12:00 UTC (1 events)

AdministratorAccess was attached directly to a user. Attackers grant themselves admin rights to keep control of the account.

**Recommended response**

1. Identify who made the change and the target identity.
2. Detach the policy if unapproved and review recent actions by both identities.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:12:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"aws-cli/2.17.0","requestParameters":{"userName":"bob","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>

### 8. [HIGH] GuardDuty detector disabled or deleted

- **Rule:** `AWS-102`
- **MITRE ATT&CK:** Defense Evasion / [T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:14:00 to 10:14:00 UTC (1 events)

GuardDuty threat detection was turned off for the account.

**Recommended response**

1. Re-create or re-enable the detector.
2. Review the identity's activity around the time of the change.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:14:00Z","eventSource":"guardduty.amazonaws.com","eventName":"DeleteDetector","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"aws-cli/2.17.0","requestParameters":{"detectorId":"12abc34d567e8fa901bc2d34e56789f0"},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>

### 9. [HIGH] S3 Block Public Access removed

- **Rule:** `AWS-104`
- **MITRE ATT&CK:** Collection / [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:18:00 to 10:18:00 UTC (1 events)

S3 Block Public Access was deleted at bucket or account level. This is a common step before exposing data publicly.

**Recommended response**

1. Restore Block Public Access.
2. Review bucket policies and ACLs for public grants.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:18:00Z","eventSource":"s3.amazonaws.com","eventName":"DeleteBucketPublicAccessBlock","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"aws-cli/2.17.0","requestParameters":{"bucketName":"acme-finance-reports","publicAccessBlock":""},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>

### 10. [HIGH] S3 bucket ACL grants public access

- **Rule:** `AWS-105`
- **MITRE ATT&CK:** Collection / [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:19:00 to 10:19:00 UTC (1 events)

A bucket ACL was changed to grant access to AllUsers or AuthenticatedUsers.

**Recommended response**

1. Remove the public grant and enable Object Ownership (bucket owner enforced).
2. Check S3 server access logs for downloads while the bucket was public.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:19:00Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketAcl","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"aws-cli/2.17.0","requestParameters":{"bucketName":"acme-finance-reports","AccessControlPolicy":{"AccessControlList":{"Grant":[{"Grantee":{"URI":"http://acs.amazonaws.com/groups/global/AllUsers"},"Permission":"READ"}]}}},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>

### 11. [HIGH] Direct root login over SSH

- **Rule:** `SSH-004`
- **MITRE ATT&CK:** Initial Access / [T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- **Entity:** `host=web01, src_ip=192.0.2.20`
- **Window:** 2026-10-14 11:15:00 to 11:15:00 UTC (1 events)

The root account logged in directly over SSH. Direct root login removes accountability and should be disabled with PermitRootLogin no.

**Recommended response**

1. Confirm with the system owner whether this login was expected.
2. Set PermitRootLogin to no in sshd_config and reload sshd.
3. Require administrators to log in as themselves and use sudo.

<details><summary>Evidence</summary>

```
Oct 14 11:15:00 web01 sshd[2500]: Accepted publickey for root from 192.0.2.20 port 60111 ssh2: RSA SHA256:q9w
```

</details>

### 12. [MEDIUM] SSH brute force from a single source

- **Rule:** `SSH-001`
- **MITRE ATT&CK:** Credential Access / [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- **Entity:** `src_ip=203.0.113.45`
- **Window:** 2026-10-14 09:01:00 to 09:04:07 UTC (12 events)

Five or more failed SSH logins from the same IP address within five minutes. Typical of automated password guessing against an exposed SSH service.

**Recommended response**

1. Check whether the source IP belongs to your organization or a known scanner.
2. Confirm no successful login followed from the same IP (see SSH-003).
3. Block the IP at the firewall or with fail2ban if it is external.
4. Disable password authentication and require SSH keys on the host.

<details><summary>Evidence</summary>

```
Oct 14 09:01:00 web01 sshd[2200]: Failed password for root from 203.0.113.45 port 51000 ssh2
Oct 14 09:01:17 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2
Oct 14 09:01:34 web01 sshd[2202]: Failed password for invalid user test from 203.0.113.45 port 51002 ssh2
Oct 14 09:01:51 web01 sshd[2203]: Failed password for invalid user oracle from 203.0.113.45 port 51003 ssh2
Oct 14 09:02:08 web01 sshd[2204]: Failed password for ubuntu from 203.0.113.45 port 51004 ssh2
Oct 14 09:02:25 web01 sshd[2205]: Failed password for ubuntu from 203.0.113.45 port 51005 ssh2
Oct 14 09:02:42 web01 sshd[2206]: Failed password for root from 203.0.113.45 port 51006 ssh2
Oct 14 09:02:59 web01 sshd[2207]: Failed password for ubuntu from 203.0.113.45 port 51007 ssh2
Oct 14 09:03:16 web01 sshd[2208]: Failed password for invalid user postgres from 203.0.113.45 port 51008 ssh2
Oct 14 09:03:33 web01 sshd[2209]: Failed password for ubuntu from 203.0.113.45 port 51009 ssh2
... 2 more events
```

</details>

### 13. [MEDIUM] Interactive root shell through sudo

- **Rule:** `LNX-003`
- **MITRE ATT&CK:** Privilege Escalation / [T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/)
- **Entity:** `host=web01, user=ubuntu`
- **Window:** 2026-10-14 09:07:00 to 09:07:00 UTC (1 events)

A user used sudo to open an interactive root shell instead of running a specific command. Common right after an account takeover.

**Recommended response**

1. Check whether the user normally administers this host.
2. Review commands executed in the root shell.

<details><summary>Evidence</summary>

```
Oct 14 09:07:00 web01 sudo[2310]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
```

</details>

### 14. [MEDIUM] New local user account created

- **Rule:** `LNX-001`
- **MITRE ATT&CK:** Persistence / [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- **Entity:** `host=web01, user=sysupdate`
- **Window:** 2026-10-14 09:08:00 to 09:08:00 UTC (1 events)

A new local account was created. Attackers add accounts to keep access after the initial compromise.

**Recommended response**

1. Verify the account against an approved change ticket.
2. Disable the account if it is not authorized and review who created it.

<details><summary>Evidence</summary>

```
Oct 14 09:08:00 web01 useradd[2320]: new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1
```

</details>

### 15. [MEDIUM] Console login without MFA

- **Rule:** `AWS-002`
- **MITRE ATT&CK:** Initial Access / [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 09:40:00 to 10:05:00 UTC (2 events)

A user signed in to the AWS console with only a password. Stolen passwords are enough to take over accounts without MFA.

**Recommended response**

1. Contact the user and confirm the login.
2. Enforce MFA with an IAM policy that denies actions when aws:MultiFactorAuthPresent is false.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T09:40:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"192.0.2.30","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:05:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
```

</details>

### 16. [MEDIUM] Repeated failed console logins

- **Rule:** `AWS-003`
- **MITRE ATT&CK:** Credential Access / [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:00:00 to 10:03:00 UTC (4 events)

Three or more failed console logins for the same user within ten minutes.

**Recommended response**

1. Check the source IPs and whether a success followed.
2. Reset the password if the user did not make these attempts.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:00:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Failure"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:01:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Failure"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:02:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Failure"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:03:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Failure"},"recipientAccountId":"111122223333","additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com/"}}
```

</details>

### 17. [MEDIUM] Burst of access-denied API calls

- **Rule:** `AWS-006`
- **MITRE ATT&CK:** Discovery / [T1580 Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:06:00 to 10:08:23 UTC (12 events)

Ten or more denied API calls from one identity in five minutes. Stolen keys are often used to probe which permissions they have.

**Recommended response**

1. Check whether the identity's access keys were used from an unusual IP or user agent.
2. Deactivate the keys if the activity is not explained.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:06:00Z","eventSource":"iam.amazonaws.com","eventName":"ListUsers","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:06:13Z","eventSource":"iam.amazonaws.com","eventName":"ListRoles","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:06:26Z","eventSource":"iam.amazonaws.com","eventName":"GetAccountAuthorizationDetails","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:06:39Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"Client.UnauthorizedOperation","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:06:52Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeSecurityGroups","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"Client.UnauthorizedOperation","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:07:05Z","eventSource":"secretsmanager.amazonaws.com","eventName":"ListSecrets","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:07:18Z","eventSource":"secretsmanager.amazonaws.com","eventName":"GetSecretValue","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:07:31Z","eventSource":"kms.amazonaws.com","eventName":"ListKeys","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:07:44Z","eventSource":"rds.amazonaws.com","eventName":"DescribeDBInstances","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:07:57Z","eventSource":"lambda.amazonaws.com","eventName":"ListFunctions","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"Boto3/1.35.0","requestParameters":null,"responseElements":null,"recipientAccountId":"111122223333","errorCode":"AccessDenied","errorMessage":"User is not authorized to perform this operation"}
... 2 more events
```

</details>

### 18. [MEDIUM] Security group opened to the internet

- **Rule:** `AWS-103`
- **MITRE ATT&CK:** Defense Evasion / [T1562.007 Impair Defenses: Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)
- **Entity:** `user=bob`
- **Window:** 2026-10-14 10:16:00 to 10:16:00 UTC (1 events)

An inbound security group rule now allows traffic from 0.0.0.0/0.

**Recommended response**

1. Check which port was opened. SSH (22) and RDP (3389) to the internet are high risk.
2. Restrict the rule to known IP ranges or use Systems Manager Session Manager instead.

<details><summary>Evidence</summary>

```
{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111122223333","userName":"bob","arn":"arn:aws:iam::111122223333:user/bob"},"eventTime":"2026-10-14T10:16:00Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","awsRegion":"eu-west-3","sourceIPAddress":"203.0.113.140","userAgent":"aws-cli/2.17.0","requestParameters":{"groupId":"sg-0a1b2c3d4e5f67890","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}},"responseElements":null,"recipientAccountId":"111122223333"}
```

</details>
