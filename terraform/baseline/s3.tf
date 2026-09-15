# VULN #1 — Public S3 bucket (A01-style broken access control for cloud).
# All four public-access protections are explicitly disabled, and a bucket
# policy grants anonymous s3:GetObject to everyone. This is the single most
# common real-world cloud breach pattern. Maps to CIS AWS Foundations 2.1.5
# (S3 Block Public Access).
#
# SAFETY: this bucket is intentionally public once applied. Never put real
# or sensitive data in it — only throwaway test objects for the exploit
# writeup, and only for as long as it takes to capture evidence before
# `terraform destroy`.
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "data" {
  bucket        = "${var.project_name}-data-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false # VULN
  block_public_policy     = false # VULN
  ignore_public_acls      = false # VULN
  restrict_public_buckets = false # VULN
}

resource "aws_s3_bucket_policy" "data_public_read" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}

# VULN #4 — Unencrypted storage. No server-side encryption configuration is
# attached to this bucket, so objects land without SSE. Maps to CIS AWS
# Foundations 2.1.1.
#
# (Deliberately absent: an aws_s3_bucket_server_side_encryption_configuration
# resource. The fix adds one with SSE-S3 or SSE-KMS.)
