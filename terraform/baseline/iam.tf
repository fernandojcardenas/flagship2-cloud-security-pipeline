# VULN #2 — Overly permissive IAM policy. Action "*" / Resource "*" grants
# full administrative access to anything that assumes this role: one
# compromised credential using this role is a fully compromised account.
# Maps to CIS AWS Foundations 1.16 (no policies with full "*:*"
# administrative privileges).
resource "aws_iam_role" "app" {
  name = "${var.project_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_policy" "app_admin" {
  #checkov:skip=CKV_AWS_62:VULN #2 seeded (full "*:*" admin), fix pending
  #checkov:skip=CKV_AWS_63:VULN #2 seeded ("*" action), fix pending
  #checkov:skip=CKV_AWS_355:VULN #2 seeded ("*" resource), fix pending
  #checkov:skip=CKV_AWS_286:VULN #2 seeded (privilege escalation), fix pending
  #checkov:skip=CKV_AWS_287:VULN #2 seeded (credentials exposure), fix pending
  #checkov:skip=CKV_AWS_288:VULN #2 seeded (data exfiltration), fix pending
  #checkov:skip=CKV_AWS_289:VULN #2 seeded (permissions management), fix pending
  #checkov:skip=CKV_AWS_290:VULN #2 seeded (unconstrained write), fix pending
  #checkov:skip=CKV2_AWS_40:VULN #2 seeded (full IAM privileges), fix pending
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

resource "aws_iam_role_policy_attachment" "app_admin" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_admin.arn
}

# VULN #5 — No MFA / no key rotation. This service user gets a long-lived
# access key with no rotation policy and no MFA requirement enforced.
# Terraform can't "seed" the absence of MFA directly — that's account/user
# state, not a declarable resource — so static IaC scanning can only flag
# that an IAM user exists at all (Checkov CKV_AWS_273). Stage 3's posture
# check catches the real problem by reading the deployed user's access keys
# and MFA devices back from the API. Key *age* can't be shown on a fresh
# deploy; that part stays a documented limitation. Maps to CIS AWS
# Foundations 1.10 / 1.12 / 1.14.
resource "aws_iam_user" "svc" {
  #checkov:skip=CKV_AWS_273:VULN #5 seeded (long-lived IAM user instead of SSO), fix pending
  name = "${var.project_name}-svc-user"
}

resource "aws_iam_access_key" "svc" {
  user = aws_iam_user.svc.name
}
