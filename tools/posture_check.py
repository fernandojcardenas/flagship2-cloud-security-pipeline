#!/usr/bin/env python3
"""Check the deployed configuration of the six seeded misconfigurations.

Runs against whatever endpoint MOTO_ENDPOINT points at (default: a local
Moto server) after tools/local_check.sh has applied terraform/baseline to it.
Each check reads the configuration back through the AWS API, the way a
posture scanner would, and reports whether the control is met.

What this proves and what it doesn't: it shows what the Terraform actually
*configured* (flags, policies, rules), read back from an API rather than
from the source. It does not show what AWS *enforces*. Moto doesn't model
everything AWS enforces (for example it ignores S3 Block Public Access when
deciding whether an anonymous request succeeds); see docs/ci-pipeline.md.

Exit status is non-zero when any result differs from what's expected:
a fixed VULN that fails again, or a VULN listed as open that now passes
(so this list and the writeups can't drift apart).
"""
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

# Seeded misconfigurations not fixed yet. A fix commit removes its number.
KNOWN_OPEN = {3, 4, 5, 6}

PREFIX = os.environ.get("PROJECT_NAME", "flagship2-baseline")
ENDPOINT = os.environ.get("MOTO_ENDPOINT", "http://localhost:5000")


def client(service):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


s3, iam, ec2, cloudtrail = (client(n) for n in ("s3", "iam", "ec2", "cloudtrail"))


def as_list(value):
    return value if isinstance(value, list) else [value]


def bucket(kind):
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]
             if b["Name"].startswith(f"{PREFIX}-{kind}-")]
    if len(names) != 1:
        raise SystemExit(f"expected one {kind} bucket, found {names}")
    return names[0]


def public_access_blocked(name):
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False, "no public access block"
        raise
    off = [k for k in ("BlockPublicAcls", "BlockPublicPolicy",
                       "IgnorePublicAcls", "RestrictPublicBuckets") if not cfg.get(k)]
    return (not off), ("all four settings on" if not off else "off: " + ", ".join(off))


def public_policy_statements(name):
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return []
        raise
    found = []
    for st in as_list(policy.get("Statement", [])):
        principal = st.get("Principal")
        if st.get("Effect") == "Allow" and (principal == "*" or
                                            (isinstance(principal, dict) and "*" in as_list(principal.get("AWS", [])))):
            found.append(",".join(as_list(st.get("Action"))))
    return found


def vuln1():
    name = bucket("data")
    blocked, detail = public_access_blocked(name)
    public = public_policy_statements(name)
    if public:
        detail += "; bucket policy allows " + "/".join(public) + " to everyone"
    else:
        detail += "; no public bucket policy"
    return blocked and not public, detail


def vuln2():
    bad = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for p in page["Policies"]:
            doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
            doc = doc["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            for st in as_list(doc.get("Statement", [])):
                if (st.get("Effect") == "Allow" and "*" in as_list(st.get("Action", []))
                        and "*" in as_list(st.get("Resource", []))):
                    bad.append(p["PolicyName"])
    return not bad, ("Action \"*\" on Resource \"*\": " + ", ".join(bad)) if bad else "no \"*:*\" policies"


def vuln3():
    bad = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for perm in sg.get("IpPermissions", []):
            proto = perm.get("IpProtocol")
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            covers_ssh = proto == "-1" or (proto == "tcp" and lo <= 22 <= hi)
            world = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            world += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
            if covers_ssh and world:
                bad.append(sg["GroupName"])
    return not bad, ("port 22 open to the internet: " + ", ".join(bad)) if bad else "no SSH from 0.0.0.0/0"


def vuln4():
    name = bucket("data")
    try:
        rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
        algos = [r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in rules]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
            raise
        algos = []
    ok = "aws:kms" in algos
    return ok, ("default encryption: " + (", ".join(algos) if algos else "none reported") +
                ("" if ok else " (control needs SSE-KMS)"))


def vuln5():
    bad = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            if not u["UserName"].startswith(PREFIX):
                continue
            keys = [k for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                    if k["Status"] == "Active"]
            mfa = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
            if keys and not mfa:
                bad.append(u["UserName"])
    return not bad, ("active access key, no MFA: " + ", ".join(bad)) if bad else "no keyed users without MFA"


def vuln6():
    trails = [t for t in cloudtrail.describe_trails()["trailList"] if t["Name"].startswith(PREFIX)]
    if not trails:
        return False, "no trail"
    t = trails[0]
    missing = [label for key, label in (("IsMultiRegionTrail", "multi-region"),
                                        ("LogFileValidationEnabled", "log file validation"))
               if not t.get(key)]
    return not missing, ("missing: " + ", ".join(missing)) if missing else "multi-region, log validation on"


def cloudtrail_bucket():
    return public_access_blocked(bucket("cloudtrail"))


CHECKS = [
    (1, "Public S3 bucket", "2.1.5", vuln1),
    (2, "Overly permissive IAM policy", "1.16", vuln2),
    (3, "Security group open to 0.0.0.0/0 on SSH", "5.2", vuln3),
    (4, "Unencrypted S3 storage", "2.1.1", vuln4),
    (5, "No MFA / no key rotation on IAM user", "1.10 / 1.14", vuln5),
    (6, "CloudTrail not multi-region, no log validation", "3.1 / 3.2", vuln6),
    (None, "CloudTrail log bucket public access (not seeded)", "2.1.5", cloudtrail_bucket),
]


def main():
    rows, unexpected = [], []
    for num, title, cis, fn in CHECKS:
        passed, detail = fn()
        expected_pass = num not in KNOWN_OPEN
        state = "pass" if passed else ("open (seeded)" if not expected_pass else "FAIL")
        if passed != expected_pass:
            unexpected.append(f"#{num or '-'} {title}: "
                              + ("passes but is still listed in KNOWN_OPEN" if passed else "fails"))
            state = "UNEXPECTED " + state
        rows.append(f"| {num or '—'} | {title} | {cis} | {state} | {detail} |")

    table = "\n".join(["| # | Control | CIS | Result | What the API returned |",
                       "|---|---|---|---|---|", *rows])
    print(table)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("### Posture checks (Moto)\n\n" + table + "\n")
    if unexpected:
        print("\nUnexpected results:\n- " + "\n- ".join(unexpected), file=sys.stderr)
        return 1
    print(f"\nAll results as expected ({len(KNOWN_OPEN)} seeded misconfigurations still open).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
