# VULN #1: Public S3 bucket

**CIS AWS Foundations Benchmark control:** 2.1.5

**Status:** Exploited against real AWS (2026-09-15). Fixed in code and
confirmed by both static scanners (2026-10-01). Live re-check against AWS
still pending — see "Live re-verification" below.

## Where it's seeded

The vulnerable version is preserved at the `vulnerable-baseline` tag. There,
`terraform/baseline/s3.tf` provisions the `data` bucket with two deliberate
misconfigurations:

- `aws_s3_bucket_public_access_block.data` — all four block-public flags
  (`block_public_acls`, `block_public_policy`, `ignore_public_acls`,
  `restrict_public_buckets`) set to `false`
- `aws_s3_bucket_policy.data_public_read` — a bucket policy with
  `Sid: "PublicReadGetObject"`, `Principal: "*"`, `Action: "s3:GetObject"`,
  `Resource: "arn:aws:s3:::<bucket>/*"`

## Provisioning

Applied for real against AWS account `<account-id redacted>`, region `us-east-1`, via
`terraform apply` on 2026-09-15. Resulting bucket:
`flagship2-baseline-data-5e8961a0`.

```
$ terraform output
cloudtrail_bucket_name = "flagship2-baseline-cloudtrail-5e8961a0"
public_bucket_name = "flagship2-baseline-data-5e8961a0"
svc_user_name = "flagship2-baseline-svc-user"
wide_open_security_group_id = "sg-0497938709541ff0c"
```

## Exploit

Uploaded a test object using the project's own authenticated AWS CLI session
(the bucket owner, not an attacker):

```
$ echo "flagship2 exploit evidence - public bucket read test" > test-public-file.txt
$ aws s3 cp test-public-file.txt s3://flagship2-baseline-data-5e8961a0/test-public-file.txt
upload: ./test-public-file.txt to s3://flagship2-baseline-data-5e8961a0/test-public-file.txt
```

Then fetched the object with a plain, unauthenticated `curl` request — no AWS
credentials, no request signing, nothing an outside attacker wouldn't also
have:

```
$ curl -s https://flagship2-baseline-data-5e8961a0.s3.amazonaws.com/test-public-file.txt
flagship2 exploit evidence - public bucket read test
```

The object came back in full. That's the exploit: anyone on the internet who
knows (or guesses, or finds via logs/URLs/predictable naming) an object key
can read it, with zero credentials.

Anonymous *listing* was also attempted, and denied:

```
$ aws s3 ls s3://flagship2-baseline-data-5e8961a0 --no-sign-request

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```

Worth stating precisely rather than overstating: the bucket policy grants
`s3:GetObject` to `Principal: "*"` but not `s3:ListBucket`, so the exposure
is "read any object if you know its key," not "browse the whole bucket."
Still a real, high-severity misconfiguration under CIS 2.1.5 — object keys
leak constantly through logs, referrer headers, and predictable naming — but
the blast radius is narrower than a fully browsable public bucket, and it's
worth documenting that distinction rather than flattening it.

## Teardown

Torn down immediately after capturing the evidence above, per this project's
rule against leaving a public/vulnerable resource live any longer than it
takes to prove the point:

```
$ terraform destroy
...
Destroy complete! Resources: 13 destroyed.
```

## Fix

In `terraform/baseline/s3.tf`:

- All four `aws_s3_bucket_public_access_block.data` flags set to `true`.
- `aws_s3_bucket_policy.data_public_read` removed entirely. Nothing in this
  project needs anonymous reads, so the fix is no public policy at all, not
  a narrower one.

The output `public_bucket_name` was renamed `data_bucket_name`, since the
bucket is no longer public. The provisioning output above is the original
run and keeps the old name.

### Static scan, before and after

Run locally with Checkov 3.3.22 and tfsec v1.28.14, limited to the S3
public-access checks. Checkov's banner, blank lines and "Guide:" URL lines
are trimmed; nothing else is.

Before (`vulnerable-baseline`):

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_53,CKV_AWS_54,CKV_AWS_55,CKV_AWS_56,CKV_AWS_70,CKV2_AWS_6
terraform scan results:
Passed checks: 0, Failed checks: 7, Skipped checks: 0
Check: CKV_AWS_53: "Ensure S3 bucket has block public ACLS enabled"
	FAILED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_54: "Ensure S3 bucket has block public policy enabled"
	FAILED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_56: "Ensure S3 bucket has 'restrict_public_buckets' enabled"
	FAILED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_55: "Ensure S3 bucket has ignore public ACLs enabled"
	FAILED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_70: "Ensure S3 bucket does not allow an action with any Principal"
	FAILED for resource: aws_s3_bucket_policy.data_public_read
	File: /s3.tf:29-46
Check: CKV2_AWS_6: "Ensure that S3 bucket has a Public Access block"
	FAILED for resource: aws_s3_bucket.data
	File: /s3.tf:15-18
Check: CKV2_AWS_6: "Ensure that S3 bucket has a Public Access block"
	FAILED for resource: aws_s3_bucket.cloudtrail
	File: /cloudtrail.tf:7-10
```

The last finding is the CloudTrail log bucket, which had no public access
block at all. It isn't one of the six seeded misconfigurations, but a
trail's logs should never be public, so the same commit gives that bucket a
full public access block too.

tfsec on the same code reports `aws-s3-block-public-acls`,
`aws-s3-block-public-policy`, `aws-s3-ignore-public-acls` and
`aws-s3-no-public-buckets`, all HIGH, on
`aws_s3_bucket_public_access_block.data` (lines 23–26, one per `false` flag).

After (the fix):

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_53,CKV_AWS_54,CKV_AWS_55,CKV_AWS_56,CKV_AWS_70,CKV2_AWS_6
terraform scan results:
Passed checks: 10, Failed checks: 0, Skipped checks: 0
Check: CKV_AWS_53: "Ensure S3 bucket has block public ACLS enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.cloudtrail
	File: /cloudtrail.tf:19-26
Check: CKV_AWS_54: "Ensure S3 bucket has block public policy enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.cloudtrail
	File: /cloudtrail.tf:19-26
Check: CKV_AWS_56: "Ensure S3 bucket has 'restrict_public_buckets' enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.cloudtrail
	File: /cloudtrail.tf:19-26
Check: CKV_AWS_55: "Ensure S3 bucket has ignore public ACLs enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.cloudtrail
	File: /cloudtrail.tf:19-26
Check: CKV_AWS_53: "Ensure S3 bucket has block public ACLS enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_54: "Ensure S3 bucket has block public policy enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_56: "Ensure S3 bucket has 'restrict_public_buckets' enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV_AWS_55: "Ensure S3 bucket has ignore public ACLs enabled"
	PASSED for resource: aws_s3_bucket_public_access_block.data
	File: /s3.tf:20-27
Check: CKV2_AWS_6: "Ensure that S3 bucket has a Public Access block"
	PASSED for resource: aws_s3_bucket.cloudtrail
	File: /cloudtrail.tf:9-13
Check: CKV2_AWS_6: "Ensure that S3 bucket has a Public Access block"
	PASSED for resource: aws_s3_bucket.data
	File: /s3.tf:14-18
```

`CKV_AWS_70` no longer appears because the public policy it flagged no
longer exists. tfsec reports the same four checks as passed for both
buckets.

CI now enforces this: these checks fail the build if the public access block
is weakened again. To confirm, the old `s3.tf` was put back temporarily and
both scanners failed (Checkov exit 1 with 6 findings, tfsec exit 1 with 4
HIGH).

## Live re-verification (pending)

Static scans prove what the Terraform says, not what AWS does. Still to do,
in a short-lived apply:

- Apply the fixed baseline, upload a test object as the bucket owner.
- Re-run the same unauthenticated `curl`; expected: `AccessDenied` instead
  of the object body.
- Capture that output here as the after-state, then `terraform destroy`.
