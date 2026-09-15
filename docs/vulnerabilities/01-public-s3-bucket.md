# VULN #1: Public S3 bucket

**CIS AWS Foundations Benchmark control:** 2.1.5

**Status:** Exploited against real AWS. Fix not yet applied — see "Fix" below.

## Where it's seeded

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

## Fix (not yet applied)

Planned for a follow-up run:

- Set all four `aws_s3_bucket_public_access_block.data` flags to `true`
- Remove `aws_s3_bucket_policy.data_public_read` entirely
- Re-apply, re-run the same `curl` request, and confirm it now fails
  (expected: `AccessDenied` / blocked, instead of the object body coming
  back)
- Capture that after-state as the "fixed" evidence, then destroy again
