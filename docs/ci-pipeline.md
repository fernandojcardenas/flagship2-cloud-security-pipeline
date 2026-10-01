# Cloud security pipeline

Status: **Stages 1–2 live; Stage 3 waiting for a scoped AWS account.**

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

Before the scanners, the same job runs `terraform fmt -check` and
`terraform validate`, so a scan never runs on code that wouldn't apply.

### First run, and why it failed

CI run #1 (2026-09-15, the scaffold commit) failed in Stage 1, as it
should have: the baseline is deliberately insecure. GitHub showed 10
Checkov annotations; reproducing the scan locally (Checkov 3.3.22, tfsec
v1.28.14) gave the full picture: **37 Checkov failures and 27 tfsec
results** across 13 resources. tfsec never ran in CI, because the step
before it had already failed.

Sorting those findings showed three kinds:

1. **The six seeded misconfigurations**, as intended (for example
   `CKV_AWS_24` on the SSH rule and nine IAM checks on the `"*"` policy).
2. **Real gaps nobody seeded.** The CloudTrail log bucket had no public
   access block. That's now fixed, not suppressed.
3. **Controls a short-lived lab doesn't need** (versioning, replication and
   so on; see below).

### How findings are handled

Stage 1 fails the build on any finding that isn't explicitly suppressed.
Suppressions come in two kinds:

- **Inline, on one resource, with a reason.** Each seeded misconfiguration
  that isn't fixed yet carries `#checkov:skip=<id>:VULN #n seeded ... fix
  pending` and a matching `#tfsec:ignore:<rule>` on its own resource. The
  commit that fixes a VULN deletes its suppressions, so from then on CI
  guards the fix. Because they're per-resource, a *new* resource with the
  same mistake still fails. This was tested: adding a second security group
  open to `0.0.0.0/0` on SSH failed both scanners.
- **Project-wide, in `.checkov.yaml` and `terraform/baseline/.tfsec/config.yml`.**
  Kept to controls that add cost or moving parts to buckets that only exist
  for minutes:

| Control | Checkov | tfsec | Why it's accepted here | In production |
|---|---|---|---|---|
| S3 server access logging | CKV_AWS_18 | aws-s3-enable-bucket-logging | Needs a third bucket; CloudTrail already records API calls | Required |
| S3 versioning | CKV_AWS_21 | aws-s3-enable-versioning | Buckets are destroyed after each run | Required for data and log buckets |
| Cross-region replication | CKV_AWS_144 | — | Doubles storage for throwaway buckets | Depends on recovery needs |
| Lifecycle configuration | CKV2_AWS_61 | — | Nothing lives long enough to expire | Recommended |
| Event notifications | CKV2_AWS_62 | — | No consumer for the events | Depends on the workload |

A few more are accepted inline on a single resource, with the reason in
the comment: no paid KMS keys (CloudTrail and its log bucket use SSE-S3),
no SNS topic for the trail, no instance attached to the security group,
and CloudWatch Logs for the trail, deferred to Flagship 3 (detection
engineering), where it's needed.

Current state: Checkov 33 passed, 0 failed; tfsec 16 passed, 0 problems.

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
