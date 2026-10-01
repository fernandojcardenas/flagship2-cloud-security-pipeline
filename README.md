# Flagship 2: Cloud Security Pipeline

Status: **all 6 seeded misconfigurations fixed** (see
[docs/vulnerabilities/](docs/vulnerabilities/README.md)). All three CI
stages run and pass. This README will grow the same way
Flagship 1's did — methodology and findings sections get added once there's
something real to report, not written in advance of it.

The original, fully vulnerable baseline is kept at the
[`vulnerable-baseline`](../../tree/vulnerable-baseline) tag.

A Terraform baseline for a small AWS footprint (S3, IAM, a security group,
CloudTrail), seeded with six deliberate misconfigurations, each mapped to
a CIS AWS Foundations Benchmark control (numbering from v1.4.0):

1. Public S3 bucket
2. Overly permissive IAM policy (`Action: "*"`, `Resource: "*"`)
3. Security group open to `0.0.0.0/0` on SSH
4. S3 buckets accept requests without TLS (reframed from "unencrypted storage",
   which AWS made impossible in 2023; see the [writeup](docs/vulnerabilities/04-s3-requests-without-tls.md))
5. Long-lived IAM user access key, no MFA
6. CloudTrail not multi-region, no log file validation

**No AWS account needed.** Everything runs on your machine or in the CI
runner. A CI pipeline (`.github/workflows/cloud-security.yml`) runs on
every push and pull request:

1. a static IaC scan (Checkov + tfsec) of the Terraform source;
2. a secret scan (gitleaks) of the full history;
3. a deploy of the baseline to [Moto](https://github.com/getmoto/moto), a
   local AWS emulator, then a posture check that reads every seeded control
   back through the AWS API.

See `docs/ci-pipeline.md` for what each stage catches, and what an emulator
can and can't prove.

Each misconfiguration gets fixed and re-verified with real before/after
output in `docs/vulnerabilities/` (see that folder's `README.md` for
status). VULN #1 was also exploited once against a real, short-lived AWS
account (September 2026), before the project went local-only; that
evidence is kept in its writeup.

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
