# Cloud security pipeline

Status: **scaffolded, not yet run for real.** This doc will fill in with
real screenshots and findings once `.github/workflows/cloud-security.yml`
has actually run against pushed code, the same way Flagship 1's
`ci-pipeline.md` was written from real CI runs rather than written first
and matched to reality after.

`.github/workflows/cloud-security.yml` runs three stages on every push and
pull request. The first two need no live AWS account at all — they scan
the Terraform source directly:

## Stage 1: Static IaC scan — Checkov + tfsec

Scans `terraform/baseline/*.tf` for known-bad patterns without applying
anything: the public S3 bucket policy, the public-access-block settings,
the `Action: "*"` IAM policy, the `0.0.0.0/0` security group rule, and the
missing encryption/log-file-validation settings are all things a static
scanner can see directly in the HCL. Checkov is primary (large default
policy library, plus custom policies in Python/YAML if needed — the same
role custom Semgrep rules played in Flagship 1); tfsec runs second for
cross-validation.

## Stage 2: Secret scan — gitleaks

Scans the full repo history for hardcoded AWS keys or other credentials.
Leaked AWS access keys committed to a public repo are one of the most
common real-world cloud breach vectors, so this gets its own stage rather
than being folded into Stage 1.

## Stage 3: Live cloud posture scan — Prowler

**Currently disabled (`if: false`)** until `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` repo secrets exist for a dedicated, narrowly-scoped
read-only scanning IAM user. Once enabled, this runs Prowler against the
actually-provisioned AWS account and checks live resource state against
the CIS AWS Foundations Benchmark — this is the stage that catches things
Stage 1 structurally can't, because they depend on live account state
rather than the Terraform source: the IAM user's key age and MFA status
(VULN #5), and anything that drifted from what the code says (manual
console changes, provider defaults that changed between applies).

This mirrors the role real ZAP scans played in Flagship 1: SAST caught
what it could see in source, DAST caught what only showed up once the app
was actually running.
