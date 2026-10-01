# VULN #4: S3 buckets accept requests without TLS

**CIS AWS Foundations Benchmark control:** 2.1.2 in v1.4.0, the version
this project's numbering follows (2.1.1 in v3.0 and v5.0): S3 bucket
policies should deny requests that don't use TLS.

**Status:** Fixed (2026-10-01). Reframed the same day; see below. Evidence
is local only: two custom Checkov policies and the emulator posture check.
This project uses no AWS account (see
[`docs/ci-pipeline.md`](../ci-pipeline.md)).

## Why this VULN was reframed

VULN #4 was seeded as **"unencrypted S3 storage"** (CIS v1.4.0 2.1.1): the
baseline leaves out any encryption configuration. That misconfiguration no
longer exists. Since January 2023, AWS encrypts every new S3 object with
SSE-S3 by default and it can't be turned off, and later CIS versions
dropped the recommendation for that reason. Checkov agreed: its encryption
check (`CKV_AWS_19`) passed on the "unencrypted" bucket. Writing it up as
a vulnerability would have meant describing a risk that can't happen.

The baseline did have a real, current gap in the same area: **neither bucket
refused plain-HTTP requests**. Without a policy that denies requests where
`aws:SecureTransport` is false, a client can talk to the bucket over
unencrypted HTTP, and anyone on the network path can read or change the
data in transit. That's CIS v1.4.0 2.1.2, and 2.1.1 in the current
versions. VULN #4 now covers it.

The `vulnerable-baseline` tag is unchanged, and it does contain this gap:
the data bucket's only policy granted public reads, and the CloudTrail
bucket's policy only let CloudTrail write. Neither denied non-TLS requests.

## Detection: custom Checkov policies

Neither scanner catches this out of the box. tfsec has no rule for it, and
Checkov's (`CKV_AWS_379`) only examines `aws_s3_bucket_acl` resources,
which this project doesn't use. So the project adds two rules of its own in
[`checkov-policies/`](../../checkov-policies), loaded through `.checkov.yaml`:

- **`CKV2_F2_1`** (YAML graph policy): every `aws_s3_bucket` must have an
  `aws_s3_bucket_policy` attached.
- **`CKV_F2_2`** (Python): every bucket policy must contain a statement that
  denies `s3:*` to every principal when `aws:SecureTransport` is false.

Before (`vulnerable-baseline`):

```
$ checkov -d terraform/baseline --framework terraform --compact --external-checks-dir checkov-policies -c CKV2_F2_1,CKV_F2_2
terraform scan results:
Passed checks: 4, Failed checks: 2, Skipped checks: 0
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket_policy.cloudtrail
	File: /cloudtrail.tf:14-39
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket.cloudtrail
	File: /cloudtrail.tf:7-10
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket_policy.data_public_read
	File: /s3.tf:29-46
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket.data
	File: /s3.tf:15-18
Check: CKV_F2_2: "Ensure S3 bucket policies deny requests that don't use TLS"
	FAILED for resource: aws_s3_bucket_policy.cloudtrail
	File: /cloudtrail.tf:14-39
Check: CKV_F2_2: "Ensure S3 bucket policies deny requests that don't use TLS"
	FAILED for resource: aws_s3_bucket_policy.data_public_read
	File: /s3.tf:29-46
```

Both buckets had *a* policy, so `CKV2_F2_1` passes; neither policy denies
non-TLS requests, so `CKV_F2_2` fails twice.

### Testing the rules themselves

A custom rule is code, so it was tested against cases written to break it:

| Case | Expected | Result |
|---|---|---|
| Bucket with no policy | `CKV2_F2_1` fails | fails |
| Deny with `aws:SecureTransport = "true"` (condition backwards) | `CKV_F2_2` fails | fails |
| Deny on `s3:GetObject` only | `CKV_F2_2` fails | fails |
| Deny `s3:*` to `{ AWS = "*" }` with boolean `false` | `CKV_F2_2` passes | passes |

Testing found two real problems in the first version of `CKV_F2_2`:

1. Checkov passes the policy to a custom check as the unevaluated text of
   `jsonencode(...)`, and sometimes renders Terraform references with extra
   quotes (`''aws_s3_bucket.cloudtrail.arn''`). The rule couldn't parse
   those and returned "unknown", which Checkov doesn't count as a failure.
   So the backwards-condition case silently produced no result, and so
   did the *fixed* CloudTrail policy: the rule had never actually read it.
2. The fix: the rule now repairs that quoting before parsing, and it
   **fails closed**. A policy it can't read counts as a failure. If a
   future Checkov version renders policies differently, CI goes red instead
   of quietly passing. All seven policies in the tests now parse, and every
   pass or fail above is a real result.

## Fix

A TLS-only statement on each bucket. The data bucket gets a new policy:

```hcl
resource "aws_s3_bucket_policy" "data_tls_only" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}
```

The CloudTrail bucket's existing policy gets the same statement as a third
entry:

```hcl
      {
        # VULN #4 fix, applied to the log bucket too (see s3.tf).
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
```

A Deny with `Principal "*"` isn't a public grant, so it works alongside the
Block Public Access settings from VULN #1.

The same commit also writes down the encryption AWS already applies: both
buckets get an `aws_s3_bucket_server_side_encryption_configuration` with
`AES256` (SSE-S3). That's what AWS does anyway; stating it means a reviewer
(and tfsec's `aws-s3-enable-bucket-encryption`) doesn't have to know the
default. A customer-managed KMS key is optional hardening rather than a CIS
requirement, so tfsec's `aws-s3-encryption-customer-key` and Checkov's
`CKV_AWS_145` stay suppressed on these resources, with that reason inline.

## Verification

Custom Checkov policies, after:

```
$ checkov -d terraform/baseline --framework terraform --compact --external-checks-dir checkov-policies -c CKV2_F2_1,CKV_F2_2
terraform scan results:
Passed checks: 6, Failed checks: 0, Skipped checks: 0
Check: CKV_F2_2: "Ensure S3 bucket policies deny requests that don't use TLS"
	PASSED for resource: aws_s3_bucket_policy.cloudtrail
	File: /cloudtrail.tf:41-80
Check: CKV_F2_2: "Ensure S3 bucket policies deny requests that don't use TLS"
	PASSED for resource: aws_s3_bucket_policy.data_tls_only
	File: /s3.tf:43-66
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket_policy.cloudtrail
	File: /cloudtrail.tf:41-80
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket.cloudtrail
	File: /cloudtrail.tf:7-11
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket_policy.data_tls_only
	File: /s3.tf:43-66
Check: CKV2_F2_1: "Ensure every S3 bucket has a bucket policy attached"
	PASSED for resource: aws_s3_bucket.data
	File: /s3.tf:12-16
```

### Emulator posture check

Check 4 now reads each bucket's deployed policy back through the S3 API and
looks for the deny-non-TLS statement. Other rows trimmed.

Before (`vulnerable-baseline` code, checked with the current checker,
which exits 1):

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS v1.4.0 | Result | What the API returned |
|---|---|---|---|---|
| 4 | S3 bucket accepts requests without TLS | 2.1.2 | UNEXPECTED FAIL | data bucket: policy doesn't deny non-TLS requests; cloudtrail bucket: policy doesn't deny non-TLS requests |
```

After:

```
Apply complete! Resources: 16 added, 0 changed, 0 destroyed.
| # | Control | CIS v1.4.0 | Result | What the API returned |
|---|---|---|---|---|
| 4 | S3 bucket accepts requests without TLS | 2.1.2 | pass | both buckets deny requests without TLS |
```

### Regression test

The deny statement was removed from the CloudTrail bucket's policy only,
leaving the data bucket fixed. Checkov failed `CKV_F2_2` on
`aws_s3_bucket_policy.cloudtrail`, and the posture check failed with
`cloudtrail bucket: policy doesn't deny non-TLS requests`.

## What this doesn't show

No request was sent over plain HTTP to see it refused. The emulator serves
plain HTTP anyway and doesn't evaluate this condition the way AWS does.
The evidence shows each bucket's policy before and after, not a refused
request.

## Sources

- AWS Security Hub, [CIS AWS Foundations Benchmark](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html):
  requirement numbers in v1.4.0, v3.0.0 and v5.0.0 (TLS requirement: 2.1.2
  in v1.4.0, 2.1.1 in v3.0.0 and v5.0.0).
- [What's new in the CIS v2.0 benchmark for AWS](https://dev.to/aws-builders/whats-new-in-the-cis-v20-benchmark-for-aws-3d77):
  the encryption-at-rest recommendation was removed after AWS made SSE-S3
  the default in January 2023.
