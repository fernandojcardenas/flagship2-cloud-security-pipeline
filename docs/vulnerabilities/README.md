# Seeded misconfigurations

Status: **in progress.** One entry per misconfiguration as it's fixed and
re-verified, mirroring Flagship 1's writeups: real command output, not
descriptions of what an attacker "could" do. Evidence comes from the
static scanners and from deploying to the Moto emulator (Stage 3 of CI).
The project uses no AWS account; VULN #1's exploit was captured once on
real AWS before that decision.

| # | Misconfiguration | CIS AWS control | Status |
|---|---|---|---|
| 1 | Public S3 bucket | 2.1.5 | Fixed. Exploited on real AWS (Sept 2026); fix confirmed by scanners and the emulator posture check ([writeup](01-public-s3-bucket.md)) |
| 2 | Overly permissive IAM policy | 1.16 | Not started |
| 3 | Security group open to 0.0.0.0/0 on SSH | 5.2 | Not started |
| 4 | Unencrypted S3 storage | 2.1.1 | Not started |
| 5 | No MFA / no key rotation on IAM user | 1.10 / 1.12 / 1.14 | Not started |
| 6 | CloudTrail not multi-region, no log file validation | 3.1 / 3.2 | Not started |

Each row gets its own file here (`01-public-s3-bucket.md`, etc.) once it's
fixed, with real commands and real before/after output.
