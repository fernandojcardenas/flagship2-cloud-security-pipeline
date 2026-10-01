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

#tfsec:ignore:aws-s3-enable-bucket-encryption
#tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "data" {
  #checkov:skip=CKV_AWS_145:VULN #4 seeded (no customer-managed KMS key), fix pending
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

# VULN #4 — Unencrypted storage. No server-side encryption configuration is
# attached to this bucket, so objects land without SSE. Maps to CIS AWS
# Foundations 2.1.1.
#
# (Deliberately absent: an aws_s3_bucket_server_side_encryption_configuration
# resource. The fix adds one with SSE-S3 or SSE-KMS.)
