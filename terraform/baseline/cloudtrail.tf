# VULN #6 — CloudTrail not multi-region, no log file validation. A
# single-region trail misses activity everywhere else the account is
# touched, and without log file validation there's no cryptographic way to
# prove the trail wasn't tampered with after the fact. "You can't do
# detection engineering on a target with no logging" — this is the
# deliberate bridge to Flagship 3. Maps to CIS AWS Foundations 3.1 / 3.2.
resource "aws_s3_bucket" "cloudtrail" {
  #checkov:skip=CKV_AWS_145:Accepted: SSE-S3 (AWS default, set explicitly below) instead of a customer-managed KMS key
  bucket        = "${var.project_name}-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true
}

# Not one of the six seeded misconfigurations: the log bucket simply had no
# public access block, which both scanners flagged on the first CI run. The
# trail's own logs should never be public, so it's locked down here rather
# than suppressed.
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

# SSE-S3 rather than a customer-managed KMS key; see the CKV_AWS_145 note
# on the bucket.
#tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        # VULN #4 fix, applied to the log bucket too (see s3.tf).
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

#tfsec:ignore:aws-cloudtrail-enable-all-regions
#tfsec:ignore:aws-cloudtrail-enable-log-validation
#tfsec:ignore:aws-cloudtrail-enable-at-rest-encryption
#tfsec:ignore:aws-cloudtrail-ensure-cloudwatch-integration
resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_67:VULN #6 seeded (single-region trail), fix pending
  #checkov:skip=CKV_AWS_36:VULN #6 seeded (no log file validation), fix pending
  #checkov:skip=CKV_AWS_35:Accepted for the lab: no paid KMS key; logs use SSE-S3
  #checkov:skip=CKV_AWS_252:Accepted for now: no SNS delivery notifications
  #checkov:skip=CKV2_AWS_10:Deferred to Flagship 3 (detection engineering), which adds CloudWatch Logs
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  is_multi_region_trail      = false # VULN
  enable_log_file_validation = false # VULN

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_s3_bucket_public_access_block.cloudtrail,
  ]
}
