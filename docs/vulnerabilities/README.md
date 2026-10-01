# Seeded misconfigurations

Status: **all six fixed** (2026-10-01). One entry per misconfiguration as it's fixed and
re-verified, mirroring Flagship 1's writeups: real command output, not
descriptions of what an attacker "could" do. Evidence comes from the
static scanners and from deploying to the Moto emulator (Stage 3 of CI).
The project uses no AWS account; VULN #1's exploit was captured once on
real AWS before that decision.

| # | Misconfiguration | CIS v1.4.0 | Status |
|---|---|---|---|
| 1 | Public S3 bucket | 2.1.5 | Fixed. Exploited on real AWS (Sept 2026); fix confirmed by scanners and the emulator posture check ([writeup](01-public-s3-bucket.md)) |
| 2 | Overly permissive IAM policy | 1.16 | Fixed (least privilege); scanners, Cloudsplaining and the emulator posture check confirm ([writeup](02-overly-permissive-iam-policy.md)) |
| 3 | Security group open to 0.0.0.0/0 on SSH | 5.2 | Fixed (no inbound access, HTTPS-only egress); scanners and the emulator posture check confirm ([writeup](03-ssh-open-to-internet.md)) |
| 4 | S3 buckets accept requests without TLS (reframed from "unencrypted storage") | 2.1.2 | Fixed (TLS-only bucket policies); custom Checkov policies and the emulator posture check confirm ([writeup](04-s3-requests-without-tls.md)) |
| 5 | Long-lived IAM user access key, no MFA | 1.10 / 1.12 / 1.14 | Fixed (user and key removed; roles and short-lived credentials instead); Checkov and the emulator posture check confirm ([writeup](05-long-lived-access-key.md)) |
| 6 | CloudTrail not multi-region, no log file validation | 3.1 / 3.2 | Fixed (multi-region trail, log file validation on); Checkov, tfsec and the emulator posture check confirm ([writeup](06-cloudtrail-single-region.md)) |

Each row gets its own file here (`01-public-s3-bucket.md`, etc.) once it's
fixed, with real commands and real before/after output.
