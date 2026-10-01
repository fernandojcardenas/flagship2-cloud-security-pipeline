# VULN #1 — Public S3 bucket (A01-style broken access control for cloud).
# FIXED. As seeded (tag `vulnerable-baseline`), all four public-access
# protections were disabled and a bucket policy granted anonymous
# s3:GetObject to everyone; see docs/vulnerabilities/01-public-s3-bucket.md
# for the real exploit. The fix turns all four protections on and removes
# the public-read policy entirely. Maps to CIS AWS Foundations 2.1.5
# (S3 Block Public Access).
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "data" {
  #checkov:skip=CKV_AWS_145:Accepted: SSE-S3 (AWS default, set explicitly below) meets current CIS; a customer-managed KMS key is optional hardening
  bucket        = "${var.project_name}-data-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# (Removed by the fix: aws_s3_bucket_policy.data_public_read, which granted
# s3:GetObject to Principal "*". Nothing in this project needs anonymous
# reads, so the right fix is no public policy at all, not a narrower one.)

# VULN #4 — Bucket accepts requests that don't use TLS. FIXED.
#
# Reframed 2026-10-01. This was seeded as "unencrypted storage" (CIS v1.4.0
# 2.1.1), but AWS has encrypted every new bucket with SSE-S3 by default
# since January 2023, so that misconfiguration can no longer exist and
# later CIS versions dropped it. The baseline did have a real, current gap
# instead: no bucket policy refusing plain-HTTP requests (CIS v1.4.0 2.1.2;
# 2.1.1 in v3.0 and v5.0). See docs/vulnerabilities/04-s3-requests-without-tls.md.
#
# The fix: a policy on each bucket that denies any request where
# aws:SecureTransport is false. The CloudTrail bucket gets the same
# statement in cloudtrail.tf.
resource "aws_s3_bucket_policy" "data_tls_only" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}

# Encryption at rest, made explicit: SSE-S3 is what AWS applies anyway, but
# stating it means a reviewer (and tfsec) doesn't have to know the default.
# SSE-S3 rather than a customer-managed KMS key; see the CKV_AWS_145 note
# on the bucket.
#tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
