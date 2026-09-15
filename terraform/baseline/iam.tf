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

resource "aws_iam_role_policy_attachment" "app_admin" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_admin.arn
}

# VULN #5 — No MFA / no key rotation. This service user gets a long-lived
# access key with no rotation policy and no MFA requirement enforced.
# Terraform can't "seed" the absence of MFA directly — that's account/user
# state, not a declarable resource — so this is the one row in the findings
# table that static IaC scanning (Checkov/tfsec) structurally cannot catch.
# Prowler catches it at scan time by inspecting the live IAM user (key age,
# attached MFA devices), the same way manual review was the only way to
# catch Flagship 1's IDOR and plaintext-password bugs. Maps to CIS AWS
# Foundations 1.10 / 1.12 / 1.14.
resource "aws_iam_user" "svc" {
  name = "${var.project_name}-svc-user"
}

resource "aws_iam_access_key" "svc" {
  user = aws_iam_user.svc.name
}
