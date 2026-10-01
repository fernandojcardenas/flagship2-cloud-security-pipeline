# VULN #2: Overly permissive IAM policy

**CIS AWS Foundations Benchmark control:** 1.16 (no IAM policies with full
`"*:*"` administrative privileges)

**Status:** Fixed (2026-10-01). Evidence is local only: static scanners, an
offline policy analyser, and the emulator posture check. This project uses
no AWS account (see [`docs/ci-pipeline.md`](../ci-pipeline.md)).

## Where it's seeded

At the `vulnerable-baseline` tag, `terraform/baseline/iam.tf` attaches this
policy to `aws_iam_role.app`, a role meant for the app's EC2 instance:

```hcl
resource "aws_iam_policy" "app_admin" {
  name        = "${var.project_name}-overpermissive-policy"
  description = "VULN: grants unrestricted access to every action on every resource."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
```

`Action: "*"` on `Resource: "*"` is full administrator access. Anyone who
gets this role's temporary credentials (for example from a compromised
instance) controls the whole account, not just the app's data.

## What the policy allows

[Cloudsplaining](https://github.com/salesforce/cloudsplaining) 0.9.1
analyses a policy document offline and lists the known abuse paths it
enables. On the seeded policy, saved as
[`evidence/02-policy-before.json`](evidence/02-policy-before.json):

```
$ cloudsplaining scan-policy-file --input-file evidence/02-policy-before.json | grep 'Potential Issue'
Potential Issue found: Policy is capable of Privilege Escalation
Potential Issue found: Policy is capable of Data Exfiltration
Potential Issue found: Policy is capable of Resource Exposure
Potential Issue found: Policy allows ALL Actions from a service (like service:*)
Potential Issue found: Policy allows actions that return credentials
Potential Issue found: Policy is capable of Unrestricted Infrastructure Modification
```

Without the `grep`, the privilege-escalation section lists 59 methods: known ways to turn these
permissions into more access, such as creating a new access key for
another user (`iam:CreateAccessKey`) or attaching an extra policy
(`iam:AttachUserPolicy`). With `*:*` every one of them is already allowed.

Checkov flags the same policy nine ways:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_62,CKV_AWS_63,CKV_AWS_355,CKV_AWS_286,CKV_AWS_287,CKV_AWS_288,CKV_AWS_289,CKV_AWS_290,CKV2_AWS_40
terraform scan results:
Passed checks: 0, Failed checks: 9, Skipped checks: 0
Check: CKV_AWS_286: "Ensure IAM policies does not allow privilege escalation"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_290: "Ensure IAM policies does not allow write access without constraints"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_288: "Ensure IAM policies does not allow data exfiltration"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_62: "Ensure IAM policies that allow full "*-*" administrative privileges are not created"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_289: "Ensure IAM policies does not allow permissions management / resource exposure without constraints"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_287: "Ensure IAM policies does not allow credentials exposure"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_63: "Ensure no IAM policies documents allow "*" as a statement's actions"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV_AWS_355: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
Check: CKV2_AWS_40: "Ensure AWS IAM policy does not allow full IAM privileges"
	FAILED for resource: aws_iam_policy.app_admin
	File: /iam.tf:23-37
```

## Fix

The app only needs to list, read and write objects in its data bucket, so
that's all the role gets:

```hcl
resource "aws_iam_policy" "app_data_access" {
  name        = "${var.project_name}-app-data-access"
  description = "Least privilege for the app: objects in the data bucket only."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListDataBucket"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.data.arn
      },
      {
        Sid      = "ReadWriteDataObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}
```

No IAM actions, no other services, no other buckets. The nine inline
Checkov suppressions and the tfsec suppression for VULN #2 were deleted in
the same commit, and `KNOWN_OPEN` in `tools/posture_check.py` no longer
lists 2.

## Verification

### Policy analysis, after

The fixed policy as deployed (read back from the emulator, so the bucket
ARN is real; saved as
[`evidence/02-policy-after.json`](evidence/02-policy-after.json)):

```
$ cloudsplaining scan-policy-file --input-file evidence/02-policy-after.json | grep 'Potential Issue'
```

No output: Cloudsplaining finds no issues in the fixed policy.

With `--flag-all-risky-actions`, which also reports actions that are
already limited to specific resources, Cloudsplaining still notes that
`s3:GetObject` can read data and `s3:PutObject` can change it. That's true
of any app that reads and writes its own bucket, and here it's limited to
that one bucket.

### Static scan, after, and a gap it exposed

The same nine Checkov checks on the fixed Terraform:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_62,CKV_AWS_63,CKV_AWS_355,CKV_AWS_286,CKV_AWS_287,CKV_AWS_288,CKV_AWS_289,CKV_AWS_290,CKV2_AWS_40
terraform scan results:
Passed checks: 2, Failed checks: 0, Skipped checks: 0
Check: CKV_AWS_62: "Ensure IAM policies that allow full "*-*" administrative privileges are not created"
	PASSED for resource: aws_iam_policy.app_data_access
	File: /iam.tf:33-54
Check: CKV_AWS_63: "Ensure no IAM policies documents allow "*" as a statement's actions"
	PASSED for resource: aws_iam_policy.app_data_access
	File: /iam.tf:33-54
```

Only two checks report a result. The policy now refers to the bucket as
`aws_s3_bucket.data.arn`, which Checkov can't resolve before deploy, and
the other seven checks silently produce no result. So "0 failed" here does
**not** mean nine passes. Run on the same policy with the deployed ARN
written in literally, all nine pass:

```
$ checkov -d . --framework terraform --compact -c CKV_AWS_62,CKV_AWS_63,CKV_AWS_355,CKV_AWS_286,CKV_AWS_287,CKV_AWS_288,CKV_AWS_289,CKV_AWS_290,CKV2_AWS_40
terraform scan results:
Passed checks: 9, Failed checks: 0, Skipped checks: 0
Check: CKV_AWS_286: "Ensure IAM policies does not allow privilege escalation"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_290: "Ensure IAM policies does not allow write access without constraints"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_288: "Ensure IAM policies does not allow data exfiltration"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_62: "Ensure IAM policies that allow full "*-*" administrative privileges are not created"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_289: "Ensure IAM policies does not allow permissions management / resource exposure without constraints"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_287: "Ensure IAM policies does not allow credentials exposure"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_63: "Ensure no IAM policies documents allow "*" as a statement's actions"
	PASSED for resource: aws_iam_policy.literal
Check: CKV_AWS_355: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"
	PASSED for resource: aws_iam_policy.literal
Check: CKV2_AWS_40: "Ensure AWS IAM policy does not allow full IAM privileges"
	PASSED for resource: aws_iam_policy.literal
```

Because of that gap, Stage 3 (which reads the deployed policy) matters for
this VULN. Checkov still catches a regression: putting `Action "*"` /
`Resource "*"` back into the fixed policy fails Checkov with all nine
checks, and fails the posture check.

tfsec flags the `/*` in the object ARN as a wildcard (rule
`aws-iam-no-policy-wildcards`, 2 HIGH). Object-level S3 permissions can only
be granted that way, and the wildcard stays inside one bucket, so this one
policy carries an inline `#tfsec:ignore` with that reason. The cost: tfsec
alone would no longer catch a `*:*` on this resource. Checkov and the
posture check still do (tested above).

### Emulator posture check

Stage 3 deploys to Moto and reads every customer-managed policy back
through the IAM API. Other rows trimmed.

Before (`vulnerable-baseline` code, checked with the current checker, which exits 1):

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS | Result | What the API returned |
|---|---|---|---|---|
| 2 | Overly permissive IAM policy | 1.16 | UNEXPECTED FAIL | Action "*" on Resource "*": flagship2-baseline-overpermissive-policy |
```

After:

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS | Result | What the API returned |
|---|---|---|---|---|
| 2 | Overly permissive IAM policy | 1.16 | pass | no "*:*" policies |
```

## What this doesn't show

No escalation was carried out. The project has no AWS account, and an
emulator's permission checks aren't AWS's (see
[`docs/ci-pipeline.md`](../ci-pipeline.md#what-an-emulator-can-and-cant-prove)).
The evidence shows what the policy grants and that the deployed policy
changed, not an attack being stopped.
