output "public_bucket_name" {
  description = "Name of the deliberately public S3 bucket (VULN #1 / #4)."
  value       = aws_s3_bucket.data.bucket
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail log bucket."
  value       = aws_s3_bucket.cloudtrail.bucket
}

output "svc_user_name" {
  description = "IAM user with the long-lived, unrotated access key (VULN #5)."
  value       = aws_iam_user.svc.name
}

output "wide_open_security_group_id" {
  description = "Security group open to 0.0.0.0/0 on SSH (VULN #3)."
  value       = aws_security_group.wide_open.id
}

# Deliberately not outputting aws_iam_access_key.svc.id/.secret — no reason
# to print credentials to a terminal even in a scoped throwaway account.
