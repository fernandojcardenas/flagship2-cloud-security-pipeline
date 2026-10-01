# VULN #6: CloudTrail not multi-region, no log file validation

**CIS AWS Foundations Benchmark controls (v1.4.0):** 3.1 (CloudTrail
enabled in all regions), 3.2 (CloudTrail log file validation enabled)

**Status:** Fixed (2026-10-01). Evidence is local only: Checkov, tfsec and
the emulator posture check. This project uses no AWS account (see
[`docs/ci-pipeline.md`](../ci-pipeline.md)).

## Where it's seeded

At the `vulnerable-baseline` tag, `terraform/baseline/cloudtrail.tf`:

```hcl
resource "aws_cloudtrail" "main" {
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  is_multi_region_trail      = false # VULN
  enable_log_file_validation = false # VULN

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
```

Two gaps in the account's audit log:

- **Single region.** The trail records API activity in one region only.
  Anything done in any other region (an attacker starting instances in a
  region nobody watches, say) never reaches the log.
- **No log file validation.** CloudTrail can write a signed digest file
  every hour that lets you prove later whether log files were changed or
  deleted. With validation off, there's no way to show the record is
  intact, which matters most right after an incident.

## Detection, before

Checkov:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_67,CKV_AWS_36
terraform scan results:
Passed checks: 0, Failed checks: 2, Skipped checks: 0
Check: CKV_AWS_36: "Ensure CloudTrail log file validation is enabled"
	FAILED for resource: aws_cloudtrail.main
	File: /cloudtrail.tf:41-49
Check: CKV_AWS_67: "Ensure CloudTrail is enabled in all Regions"
	FAILED for resource: aws_cloudtrail.main
	File: /cloudtrail.tf:41-49
```

tfsec (v1.28.14):

```
MEDIUM aws-cloudtrail-enable-all-regions aws_cloudtrail.main line 45
HIGH aws-cloudtrail-enable-log-validation aws_cloudtrail.main line 46
```

Posture check (Stage 3), other rows trimmed. Before (`vulnerable-baseline`
code, checked with the current checker, which exits 1):

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS v1.4.0 | Result | What the API returned |
|---|---|---|---|---|
| 6 | CloudTrail not multi-region, no log file validation | 3.1 / 3.2 | UNEXPECTED FAIL | missing: multi-region, log file validation |
```

## Fix

Both settings turned on, and VULN #6's suppressions removed:

```hcl
resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_35:Accepted for the lab: no paid KMS key; logs use SSE-S3
  #checkov:skip=CKV_AWS_252:Accepted for now: no SNS delivery notifications
  #checkov:skip=CKV2_AWS_10:Deferred to Flagship 3 (detection engineering), which adds CloudWatch Logs
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  is_multi_region_trail      = true
  enable_log_file_validation = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_s3_bucket_public_access_block.cloudtrail,
  ]
}
```

The remaining suppressions on the trail are deliberate and stay, each with
its reason inline: no paid KMS key for log encryption (`CKV_AWS_35`,
tfsec `aws-cloudtrail-enable-at-rest-encryption`), no SNS notifications
(`CKV_AWS_252`), and CloudWatch Logs integration (`CKV2_AWS_10`, tfsec
`aws-cloudtrail-ensure-cloudwatch-integration`), which is deferred to
Flagship 3. `KNOWN_OPEN` in `tools/posture_check.py` is now empty.

## Verification

Checkov, after:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_67,CKV_AWS_36
terraform scan results:
Passed checks: 2, Failed checks: 0, Skipped checks: 0
Check: CKV_AWS_36: "Ensure CloudTrail log file validation is enabled"
	PASSED for resource: aws_cloudtrail.main
	File: /cloudtrail.tf:87-101
Check: CKV_AWS_67: "Ensure CloudTrail is enabled in all Regions"
	PASSED for resource: aws_cloudtrail.main
	File: /cloudtrail.tf:87-101
```

tfsec, after (the same two rules, with passed results included):

```
PASSED MEDIUM aws-cloudtrail-enable-all-regions aws_cloudtrail.main
PASSED HIGH aws-cloudtrail-enable-log-validation aws_cloudtrail.main
```

Posture check, after:

```
Apply complete! Resources: 14 added, 0 changed, 0 destroyed.
| # | Control | CIS v1.4.0 | Result | What the API returned |
|---|---|---|---|---|
| 6 | CloudTrail not multi-region, no log file validation | 3.1 / 3.2 | pass | multi-region, log validation on |
All results as expected (all six seeded misconfigurations fixed).
```

### Regression test

`is_multi_region_trail` was set back to `false` alone, leaving validation
on. Checkov failed `CKV_AWS_67`, tfsec reported
`aws-cloudtrail-enable-all-regions`, and the posture check failed with
`missing: multi-region`.

## What this doesn't show

No log files were written or checked: the emulator stores the trail's
settings but doesn't produce real CloudTrail logs or digest files, and no
`aws cloudtrail validate-logs` run was possible without an AWS account.
The evidence shows the trail's configuration before and after.

## Why it matters for Flagship 3

Detection engineering (Flagship 3) needs a complete, trustworthy record to
write detections against. A trail that misses regions or can be edited
silently is a weak foundation, so this fix is also the starting point for
that project. CloudTrail-to-CloudWatch Logs integration was left for it.
