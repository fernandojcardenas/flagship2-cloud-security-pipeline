output "data_bucket_name" {
  description = "Name of the data bucket (VULN #1 and #4, fixed)."
  value       = aws_s3_bucket.data.bucket
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail log bucket."
  value       = aws_s3_bucket.cloudtrail.bucket
}

output "app_security_group_id" {
  description = "Security group for app instances (VULN #3, fixed: no inbound access)."
  value       = aws_security_group.app.id
}
