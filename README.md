# Flagship 2: Cloud Security Pipeline

A small AWS footprint in Terraform (two S3 buckets, an IAM role, a security
group, CloudTrail), built in three passes:

- The [`vulnerable-baseline` tag](../../tree/vulnerable-baseline) is the
  original Terraform with six misconfigurations deliberately seeded into it,
  each mapped to a CIS AWS Foundations Benchmark control and marked with a
  `VULN` comment.
- The default branch fixes all six, with a writeup per misconfiguration in
  [`docs/vulnerabilities/`](docs/vulnerabilities/README.md), including real
  before/after output from every check.
- A CI pipeline (`.github/workflows/cloud-security.yml`) runs on every push
  and pull request: a static IaC scan (Checkov, with two project-specific
  rules, plus tfsec), a secret scan (gitleaks), and a deploy to
  [Moto](https://github.com/getmoto/moto), a local AWS emulator, followed by
  a posture check that reads every control back through the AWS API. See
  [`docs/ci-pipeline.md`](docs/ci-pipeline.md) for what each stage catches,
  what it misses, and what an emulator can and can't prove.

**No AWS account needed.** Everything runs on your machine or in the CI
runner. Status: **all 6 seeded misconfigurations fixed.**

## Methodology

As in Flagship 1, there are two discovery paths, kept separate on purpose:

1. **Seed, detect, fix.** Six misconfigurations were written into the
   baseline on purpose. Each one was detected, fixed, and checked again
   against the fixed code with the same tools, and each fix comes with a
   regression test: the bug (or a variant) was put back temporarily to
   confirm the checks still catch it. VULN #1 was also exploited for real
   against a short-lived AWS account (an anonymous `curl` read a file from
   the bucket) before the project went local-only. The others are shown
   through scanner output, policy analysis and the deployed configuration,
   and each writeup says plainly what that evidence does *not* show.
2. **Fix what the work itself turned up.** Several findings were never on
   the seeded list:
   - The CloudTrail log bucket had **no public access block at all**.
     Checkov and tfsec both flagged it when the first (failed) CI run was
     reproduced locally; it was fixed, not suppressed.
   - **VULN #4 no longer existed as seeded.** "Unencrypted S3 storage" became
     impossible when AWS turned on default encryption in 2023 (Checkov's
     encryption check passed on the "unencrypted" bucket). It was reframed
     to a real gap the baseline had: buckets that accept plain-HTTP requests.
   - **Neither scanner checks that gap** for these resources, so the project
     adds two custom Checkov rules. Testing the first version showed it
     silently returned "unknown" on policies it couldn't parse, including a
     fixed one, so the rule now fails closed.
   - **Checkov can go quiet.** When an IAM policy refers to a bucket by
     reference, 7 of its 9 IAM checks produce no result at all, not a pass.
     The emulator stage reads the deployed policy, which covers that.
   - **Emulators prove configuration, not enforcement.** Moto ignores S3
     Block Public Access for anonymous reads; MiniStack applies no access
     control. So no emulator "exploit" is used as evidence.

## Misconfigurations found and fixed

CIS numbering is from v1.4.0.

| # | Misconfiguration | CIS | How it was found | Fix |
|---|---|---|---|---|
| 1 | [Public S3 bucket](docs/vulnerabilities/01-public-s3-bucket.md) | 2.1.5 | Checkov (`CKV_AWS_53`–`56`, `CKV_AWS_70`) and tfsec (4 HIGH); exploited on real AWS with an anonymous `curl`. | All four Block Public Access settings on; public-read policy removed. |
| 2 | [Overly permissive IAM policy](docs/vulnerabilities/02-overly-permissive-iam-policy.md) | 1.16 | Checkov (9 IAM checks) and tfsec; Cloudsplaining listed 59 privilege-escalation methods. | Least privilege: list, read and write objects in the app's own bucket only. |
| 3 | [Security group open to the internet on SSH](docs/vulnerabilities/03-ssh-open-to-internet.md) | 5.2 | Checkov (`CKV_AWS_24`, allow-all egress `CKV_AWS_382`) and tfsec (2 CRITICAL). | No inbound rules at all (admin through Session Manager); egress HTTPS only. |
| 4 | [S3 buckets accept requests without TLS](docs/vulnerabilities/04-s3-requests-without-tls.md) (reframed) | 2.1.2 | Neither scanner covers it here: two custom Checkov rules (`CKV2_F2_1`, `CKV_F2_2`). | A policy on each bucket that denies any request without TLS. |
| 5 | [Long-lived IAM user access key, no MFA](docs/vulnerabilities/05-long-lived-access-key.md) | 1.10 / 1.12 / 1.14 | Checkov only sees that an IAM user exists (`CKV_AWS_273`); the key and MFA state are only visible to the emulator posture check. | User and key removed; roles and short-lived credentials instead. |
| 6 | [CloudTrail not multi-region, no log file validation](docs/vulnerabilities/06-cloudtrail-single-region.md) | 3.1 / 3.2 | Checkov (`CKV_AWS_67`, `CKV_AWS_36`) and tfsec. | Multi-region trail with log file validation on. |

Two of the six are the interesting ones. VULN #5 is mostly invisible to
static scanning, because the risk lives in deployed state (a key exists,
no MFA device does), not in a pattern in the source. VULN #4 needed rules
written for this project. A green static scan alone wasn't enough for
either, which is why the pipeline has a deploy-and-check stage at all.

## Running the checks locally

```
pip install checkov
checkov --config-file .checkov.yaml

# tfsec: see https://aquasecurity.github.io/tfsec/ for install options
tfsec terraform/baseline

# gitleaks: see https://github.com/gitleaks/gitleaks for install options
gitleaks detect --config .gitleaks.toml

# Deploy to a local Moto server and run the posture checks
# (needs Terraform >= 1.7 and Python 3)
pip install -r tools/requirements.txt
tools/local_check.sh
```

`tools/local_check.sh` applies a scratch copy of `terraform/baseline` with
`emulator/provider_override.tf` added, so it only ever talks to
`localhost:5000`.
