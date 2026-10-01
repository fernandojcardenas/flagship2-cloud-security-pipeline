output "data_bucket_name" {
  description = "Name of the data bucket (VULN #1, fixed; VULN #4)."
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

output "app_security_group_id" {
  description = "Security group for app instances (VULN #3, fixed: no inbound access)."
  value       = aws_security_group.app.id
}

# Deliberately not outputting aws_iam_access_key.svc.id/.secret — no reason
# to print credentials to a terminal even in a scoped throwaway account.
