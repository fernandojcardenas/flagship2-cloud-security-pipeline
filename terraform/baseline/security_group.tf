# VULN #3 — Security group open to the entire internet on SSH. FIXED.
#
# As seeded (tag `vulnerable-baseline`), this group allowed SSH (port 22)
# from 0.0.0.0/0, one of the most-scanned-for misconfigurations there is,
# plus allow-all egress. See docs/vulnerabilities/03-ssh-open-to-internet.md.
# Maps to CIS AWS Foundations 5.2.
#
# The fix removes inbound access entirely. Admins reach instances through
# AWS Systems Manager Session Manager, which works over the instance's own
# outbound HTTPS connection, so no inbound port is needed. Egress is
# narrowed from "everything" to HTTPS only.
#
# No EC2 instance is attached to this group in the baseline, so the
# configuration can be scanned and checked without paying for one.

# tfsec flags any egress to 0.0.0.0/0. HTTPS out is needed for Session
# Manager and package updates, and this lab has no VPC endpoints or NAT to
# narrow it further. Checkov's allow-all egress check (CKV_AWS_382) passes.
#tfsec:ignore:aws-ec2-no-public-egress-sgr
resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:By design: no instance is attached, to avoid paying for one
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
