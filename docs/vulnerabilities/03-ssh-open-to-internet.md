# VULN #3: Security group open to the internet on SSH

**CIS AWS Foundations Benchmark control:** 5.2 (no security groups allow
ingress from 0.0.0.0/0 to remote administration ports)

**Status:** Fixed (2026-10-01). Evidence is local only: static scanners and
the emulator posture check. This project uses no AWS account (see
[`docs/ci-pipeline.md`](../ci-pipeline.md)).

## Where it's seeded

At the `vulnerable-baseline` tag, `terraform/baseline/security_group.tf`:

```hcl
resource "aws_security_group" "wide_open" {
  name        = "${var.project_name}-wide-open-ssh"
  description = "VULN: allows inbound SSH from anywhere"

  ingress {
    description = "VULN: SSH open to the entire internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Default allow-all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

Port 22 open to `0.0.0.0/0` means any address on the internet can try to
log in over SSH. Internet-wide scanners routinely probe port 22, so a host
in this group would face password-guessing and exploit attempts as soon as
it went live. Egress was also wide open: any port, any destination.

No instance is attached to the group, so nothing was ever reachable. The
misconfiguration is in the group's rules, and that's what the scanners and
the posture check look at.

## Detection, before

Checkov, limited to its security-group checks:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_24,CKV_AWS_382,CKV_AWS_260,CKV_AWS_25,CKV_AWS_277
terraform scan results:
Passed checks: 3, Failed checks: 2, Skipped checks: 0
Check: CKV_AWS_260: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 80"
	PASSED for resource: aws_security_group.wide_open
	File: /security_group.tf:9-28
Check: CKV_AWS_277: "Ensure no security groups allow ingress from 0.0.0.0:0 to port -1"
	PASSED for resource: aws_security_group.wide_open
	File: /security_group.tf:9-28
Check: CKV_AWS_25: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389"
	PASSED for resource: aws_security_group.wide_open
	File: /security_group.tf:9-28
Check: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
	FAILED for resource: aws_security_group.wide_open
	File: /security_group.tf:9-28
Check: CKV_AWS_382: "Ensure no security groups allow egress from 0.0.0.0:0 to port -1"
	FAILED for resource: aws_security_group.wide_open
	File: /security_group.tf:9-28
```

tfsec (v1.28.14), security-group results:

```
CRITICAL aws-ec2-no-public-egress-sgr aws_security_group.wide_open line 26
CRITICAL aws-ec2-no-public-ingress-sgr aws_security_group.wide_open line 18
```

## Fix

Inbound access is removed entirely, not narrowed to a "trusted" address
range. Admins reach instances through AWS Systems Manager Session Manager,
which runs over the instance's own outbound HTTPS connection, so no inbound
port is needed. That also removes the SSH keys to manage. Egress is
narrowed from every port to HTTPS only.

```hcl
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app"
  description = "App instances: no inbound access; outbound HTTPS only"

  egress {
    description = "HTTPS out (Session Manager, package updates)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

The resource was renamed from `wide_open` to `app` (and its output to
`app_security_group_id`), since it's no longer wide open. VULN #3's inline
suppressions were deleted, and `KNOWN_OPEN` in `tools/posture_check.py`
no longer lists 3.

One judgment call: tfsec flags any egress to `0.0.0.0/0`, including HTTPS.
Session Manager and package updates need HTTPS out, and this lab has no VPC
endpoints or NAT gateway to narrow the destination further, so tfsec's
`aws-ec2-no-public-egress-sgr` is suppressed on this one group with that
reason. Checkov's allow-all egress check (`CKV_AWS_382`) passes.

## Verification

Checkov, after:

```
$ checkov -d terraform/baseline --framework terraform --compact -c CKV_AWS_24,CKV_AWS_382,CKV_AWS_260,CKV_AWS_25,CKV_AWS_277
terraform scan results:
Passed checks: 5, Failed checks: 0, Skipped checks: 0
Check: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
	PASSED for resource: aws_security_group.app
	File: /security_group.tf:20-32
Check: CKV_AWS_260: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 80"
	PASSED for resource: aws_security_group.app
	File: /security_group.tf:20-32
Check: CKV_AWS_382: "Ensure no security groups allow egress from 0.0.0.0:0 to port -1"
	PASSED for resource: aws_security_group.app
	File: /security_group.tf:20-32
Check: CKV_AWS_277: "Ensure no security groups allow ingress from 0.0.0.0:0 to port -1"
	PASSED for resource: aws_security_group.app
	File: /security_group.tf:20-32
Check: CKV_AWS_25: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389"
	PASSED for resource: aws_security_group.app
	File: /security_group.tf:20-32
```

tfsec reports no findings. Its public-ingress rule now has nothing to
flag, because the group has no inbound rules at all.

### Emulator posture check

For this fix the posture check was widened. It used to look only for SSH
open to the internet; now any inbound rule open to `0.0.0.0/0` or `::/0`
fails, on any port. Other rows trimmed.

Before (`vulnerable-baseline` code, checked with the current checker,
which exits 1):

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS | Result | What the API returned |
|---|---|---|---|---|
| 3 | Security group open to 0.0.0.0/0 on SSH | 5.2 | UNEXPECTED FAIL | open to the internet: flagship2-baseline-wide-open-ssh: port 22 (SSH) |
```

After:

```
Apply complete! Resources: 13 added, 0 changed, 0 destroyed.
| # | Control | CIS | Result | What the API returned |
|---|---|---|---|---|
| 3 | Security group open to 0.0.0.0/0 on SSH | 5.2 | pass | no inbound rules open to the internet |
```

### Regression test

To confirm a different open port would still be caught, a rule allowing
RDP (port 3389) from `0.0.0.0/0` was added to the fixed group temporarily.
All three caught it: Checkov `CKV_AWS_25` failed, tfsec reported
`aws-ec2-no-public-ingress-sgr`, and the posture check failed with
`flagship2-baseline-app: port 3389`. The old SSH-only posture check would
have missed it.

## What this doesn't show

No instance was launched and nothing was scanned over the network. The
evidence shows the group's rules before and after, not a connection
attempt being refused.
