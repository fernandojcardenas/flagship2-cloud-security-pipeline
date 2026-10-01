# VULN #3 — Security group open to the entire internet on SSH. 0.0.0.0/0
# on port 22 is one of the most-scanned-for misconfigurations that exists;
# any host in this group is reachable for brute-force/credential-stuffing
# within minutes of going live. Maps to CIS AWS Foundations 5.2.
#
# No EC2 instance is attached to this group in the baseline — the
# misconfiguration is scannable (both statically and live, once applied)
# without needing to run, and pay for, an actual instance.
#tfsec:ignore:aws-ec2-no-public-ingress-sgr
#tfsec:ignore:aws-ec2-no-public-egress-sgr
resource "aws_security_group" "wide_open" {
  #checkov:skip=CKV_AWS_24:VULN #3 seeded (SSH from 0.0.0.0/0), fix pending
  #checkov:skip=CKV_AWS_382:VULN #3 seeded (allow-all egress), fix pending
  #checkov:skip=CKV2_AWS_5:By design: no instance is attached, to avoid paying for one
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
