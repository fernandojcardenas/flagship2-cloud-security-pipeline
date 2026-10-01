# Cloud security pipeline

Status: **all three stages live. No AWS account is used anywhere.**

`.github/workflows/cloud-security.yml` runs three stages on every push and
pull request. The first two scan the source; the third deploys it to a
local AWS emulator inside the runner:

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

Current state: Checkov 37 passed, 0 failed, 9 skipped; tfsec 15 passed,
23 ignored, 0 problems.

One limit worth knowing: when a policy refers to another resource (for
example `aws_s3_bucket.data.arn`), Checkov can't resolve the value before
deploy, and several IAM checks then produce no result at all rather than a
pass. VULN #2's writeup shows this (2 of 9 checks report on the fixed
policy; all 9 pass once the real ARN is filled in). Stage 3 covers it by
reading the deployed policies.

## Stage 2: Secret scan — gitleaks

Scans the full repo history for hardcoded AWS keys or other credentials.
Leaked AWS access keys committed to a public repo are one of the most
common real-world cloud breach vectors, so this gets its own stage rather
than being folded into Stage 1.

## Stage 3: Deploy to an emulator and check posture — Moto

`tools/local_check.sh` starts [Moto](https://github.com/getmoto/moto)
(5.2.3, pinned in `tools/requirements.txt`), applies a scratch copy of
`terraform/baseline` to it with `emulator/provider_override.tf` added, then
runs `tools/posture_check.py`. The checker reads each seeded control back
through the AWS API, the way a posture scanner like Prowler would against
a real account: the bucket's public access block and policy, every
customer-managed IAM policy, security group rules (any inbound rule open to the internet), bucket encryption, IAM
users' access keys and MFA devices, and the trail's settings.

This stage catches what Stage 1 can't see in the source: the IAM user with
an active key and no MFA (VULN #5) is only visible once the user and key
exist. It also confirms the Terraform really applies.

The checker fails the build if anything differs from what's expected: a
fixed VULN that fails again, or a VULN still listed as open in
`KNOWN_OPEN` that now passes. That keeps the list and the writeups in step.

Current output (local run, 2026-10-01; the same table goes into each CI
run's summary):

```
$ tools/local_check.sh
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS | Result | What the API returned |
|---|---|---|---|---|
| 1 | Public S3 bucket | 2.1.5 | pass | all four settings on; no public bucket policy |
| 2 | Overly permissive IAM policy | 1.16 | pass | no "*:*" policies |
| 3 | Security group open to 0.0.0.0/0 on SSH | 5.2 | pass | no inbound rules open to the internet |
| 4 | Unencrypted S3 storage | 2.1.1 | open (seeded) | default encryption: none reported (control needs SSE-KMS) |
| 5 | No MFA / no key rotation on IAM user | 1.10 / 1.14 | open (seeded) | active access key, no MFA: flagship2-baseline-svc-user |
| 6 | CloudTrail not multi-region, no log validation | 3.1 / 3.2 | open (seeded) | missing: multi-region, log file validation |
| — | CloudTrail log bucket public access (not seeded) | 2.1.5 | pass | all four settings on |

All results as expected (3 seeded misconfigurations still open).
```

### What an emulator can and can't prove

This stage shows what the Terraform *configured*, read back from an API. It
does not show what AWS *enforces*. Before choosing this design, the same
Terraform was applied to two free emulators and the data bucket was read
with an anonymous `curl` (2026-10-01). "Control" means all four Block
Public Access settings on but the public bucket policy kept, a combination
AWS documents it refuses to apply.

| Anonymous request | Real AWS (VULN #1 writeup, Sept 2026) | Moto 5.2.3 | MiniStack 1.5.19 |
|---|---|---|---|
| Read object, vulnerable baseline | 200, object returned | 200 | 200 |
| Read object, fixed | not tested | 403 | 200 |
| Read object, control | not tested (AWS documents that it refuses the public policy) | 200 | 200 |
| List bucket, vulnerable baseline | AccessDenied | 200 | 200 |

Moto applies bucket policies to anonymous reads but ignores Block Public
Access and allows anonymous listing; MiniStack applies no access control.
So an "exploit" run against either would prove little, and the writeups
don't use one. LocalStack's policy enforcement is a paid feature, so it
wasn't tested.
