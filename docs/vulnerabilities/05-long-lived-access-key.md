# VULN #5: Long-lived IAM user access key, no MFA

**CIS AWS Foundations Benchmark controls (v1.4.0):** 1.10 (MFA for IAM
users with a console password), 1.12 (credentials unused for 45 days are
disabled), 1.14 (access keys rotated every 90 days)

**Status:** Fixed (2026-10-01). Evidence is local only: Checkov and the
emulator posture check. This project uses no AWS account (see
[`docs/ci-pipeline.md`](../ci-pipeline.md)).

## Where it's seeded

At the `vulnerable-baseline` tag, `terraform/baseline/iam.tf`:

```hcl
resource "aws_iam_user" "svc" {
  name = "${var.project_name}-svc-user"
}

resource "aws_iam_access_key" "svc" {
  user = aws_iam_user.svc.name
}
```

A service user with a long-lived access key: no MFA, nothing forcing
rotation, no expiry. Once created, that key works from anywhere until
someone deletes it. Keys like this leak through code repositories, CI logs,
laptops and backups, and a leaked key is just as good to whoever finds it.

To be precise about which CIS controls apply: 1.10 (MFA) covers users with
a console password, and this user has none (Checkov's `CKV2_AWS_22` passes
below). The real exposure is the stored key, which is what 1.12 and 1.14
are about. MFA wouldn't protect it anyway: calls signed with an access key
don't involve MFA unless a policy demands it.

## Detection, before

Static scanning can only see that an IAM user is defined, not its keys'
age or MFA state:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_273,CKV2_AWS_22
terraform scan results:
Passed checks: 1, Failed checks: 1, Skipped checks: 0
Check: CKV2_AWS_22: "Ensure an IAM User does not have access to the console"
	PASSED for resource: aws_iam_user.svc
	File: /iam.tf:53-55
Check: CKV_AWS_273: "Ensure access is controlled through SSO and not AWS IAM defined users"
	FAILED for resource: aws_iam_user.svc
	File: /iam.tf:53-55
```

tfsec has no finding on the user or the key.

The posture check (Stage 3) sees the deployed state. It now fails on any
project IAM user that has an active access key, and reports MFA alongside.
Other rows trimmed. Before (`vulnerable-baseline` code, checked with the
current checker, which exits 1):

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS v1.4.0 | Result | What the API returned |
|---|---|---|---|---|
| 5 | Long-lived IAM user access key, no MFA | 1.10 / 1.14 | UNEXPECTED FAIL | long-lived access key: flagship2-baseline-svc-user (1 active key, no MFA) |
```

## Fix

The user and its key are removed, not patched with MFA or a rotation
schedule. Nothing in this project needs a long-lived credential:

- Workloads on AWS use **IAM roles**, like the app role from VULN #2. AWS
  hands out temporary credentials that expire on their own.
- A workload outside AWS would also get **short-lived credentials** (OIDC
  federation, as GitHub Actions uses, or IAM Roles Anywhere), never a
  stored key.

The `svc_user_name` output, the user, the key and VULN #5's Checkov
suppression were deleted, and `KNOWN_OPEN` in `tools/posture_check.py`
no longer lists 5.

## Verification

Checkov, after: the same command prints no results, because there is no
IAM user left to check. The full scan passes (42 passed, 0 failed).

Posture check, after:

```
Apply complete! Resources: 14 added, 0 changed, 0 destroyed.
| # | Control | CIS v1.4.0 | Result | What the API returned |
|---|---|---|---|---|
| 5 | Long-lived IAM user access key, no MFA | 1.10 / 1.14 | pass | no IAM users with access keys |
```

### Regression test

A new user with an access key (`flagship2-baseline-regression-user`) was
added to the fixed Terraform temporarily. Checkov failed `CKV_AWS_273` on
it, and the posture check failed with `long-lived access key:
flagship2-baseline-regression-user (1 active key, no MFA)`.

## What this doesn't show

Key *age* (1.14's 90 days) and *unused* credentials (1.12's 45 days) can't
be demonstrated on a fresh deployment, where every key is minutes old. With
no users or keys left, there's nothing for those controls to find. No
attempt was made to use the old key.
