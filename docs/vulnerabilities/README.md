# Seeded misconfigurations

Status: **planned, not yet exploited or fixed.** This index will get one
entry per misconfiguration as it's actually provisioned, exploited against
the real (scoped, short-lived) AWS account, and fixed — mirroring
Flagship 1's exploit-and-fix writeups, with real command output and
screenshots, not descriptions of what an attacker "could" do.

| # | Misconfiguration | CIS AWS control | Status |
|---|---|---|---|
| 1 | Public S3 bucket | 2.1.5 | Not started |
| 2 | Overly permissive IAM policy | 1.16 | Not started |
| 3 | Security group open to 0.0.0.0/0 on SSH | 5.2 | Not started |
| 4 | Unencrypted S3 storage | 2.1.1 | Not started |
| 5 | No MFA / no key rotation on IAM user | 1.10 / 1.12 / 1.14 | Not started |
| 6 | CloudTrail not multi-region, no log file validation | 3.1 / 3.2 | Not started |

Each row will get its own file here (`01-public-s3-bucket.md`, etc.) once
it's actually been exploited and fixed, following the same format as
Flagship 1: real commands, real output, before/after screenshots.
