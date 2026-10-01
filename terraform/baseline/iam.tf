# VULN #2 — Overly permissive IAM policy. FIXED.
#
# As seeded (tag `vulnerable-baseline`), the app role had a policy with
# Action "*" / Resource "*": full administrative access, so one stolen
# credential for this role meant a fully compromised account (see
# docs/vulnerabilities/02-overly-permissive-iam-policy.md). Maps to CIS AWS
# Foundations 1.16 (no policies with full "*:*" administrative privileges).
#
# The fix gives the role only what the app does: list, read and write
# objects in the data bucket. No IAM actions, no other services, no other
# buckets.
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

# tfsec flags the "/*" in the object ARN below as a wildcard. Object-level S3
# permissions can only be granted that way (keys aren't known in advance),
# and the wildcard stays inside this one bucket. Checkov passes it.
#tfsec:ignore:aws-iam-no-policy-wildcards
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

resource "aws_iam_role_policy_attachment" "app_data_access" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_data_access.arn
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
