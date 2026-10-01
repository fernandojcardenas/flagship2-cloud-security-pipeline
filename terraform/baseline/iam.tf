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

# VULN #5 — Long-lived IAM user access key, no MFA. FIXED.
#
# As seeded (tag `vulnerable-baseline`), a service user
# (`flagship2-baseline-svc-user`) had a long-lived access key, with no MFA
# and nothing forcing rotation. A stored key like that works from anywhere
# until someone notices it leaked. See
# docs/vulnerabilities/05-long-lived-access-key.md. Maps to CIS AWS
# Foundations v1.4.0 1.10 / 1.12 / 1.14.
#
# The fix removes the user and its key rather than adding MFA or a rotation
# schedule: nothing in this project needs a long-lived credential. Workloads
# on AWS use IAM roles (like aws_iam_role.app above), which hand out
# temporary credentials automatically. A workload outside AWS would use
# short-lived credentials too (OIDC federation or IAM Roles Anywhere),
# never a stored key.
