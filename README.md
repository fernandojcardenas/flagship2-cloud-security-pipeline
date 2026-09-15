# Flagship 2: Cloud Security Pipeline

Status: **scaffolded, not yet built out.** This README will grow the same
way Flagship 1's did — methodology and findings sections get added once
there's something real to report, not written in advance of it.

A Terraform baseline for a small AWS footprint (S3, IAM, a security group,
CloudTrail), seeded with six deliberate misconfigurations, each mapped to
a CIS AWS Foundations Benchmark control:

1. Public S3 bucket
2. Overly permissive IAM policy (`Action: "*"`, `Resource: "*"`)
3. Security group open to `0.0.0.0/0` on SSH
4. Unencrypted S3 storage
5. No MFA / no key rotation on an IAM user
6. CloudTrail not multi-region, no log file validation

A CI pipeline (`.github/workflows/cloud-security.yml`) runs a static IaC
scan (Checkov + tfsec), a secret scan (gitleaks), and — once a scoped AWS
account is wired up — a live cloud posture scan (Prowler) against the CIS
AWS Foundations Benchmark, on every push and pull request. See
`docs/ci-pipeline.md` for what each stage catches and why.

Each misconfiguration gets exploited for real against a short-lived,
narrowly-scoped AWS environment, fixed, and re-verified, with real
before/after evidence in `docs/vulnerabilities/` — see that folder's
`README.md` for current status.

## Running the checks locally

```
pip install checkov
checkov --config-file .checkov.yaml

# tfsec: see https://aquasecurity.github.io/tfsec/ for install options
tfsec terraform/baseline

# gitleaks: see https://github.com/gitleaks/gitleaks for install options
gitleaks detect --config .gitleaks.toml
```

`terraform/baseline` is not applied by default — provisioning against real
AWS is a deliberate, manual step (see `docs/ci-pipeline.md`), not something
that happens automatically from a scaffold.
