# Points the AWS provider at a local Moto server instead of real AWS.
#
# Never lives in terraform/baseline in the repo: tools/local_check.sh copies
# the baseline to a scratch directory and drops this file next to it, so a
# normal `terraform apply` in terraform/baseline can't pick it up by
# accident. Terraform merges *_override.tf files into the provider block in
# versions.tf.
provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    cloudtrail = "http://localhost:5000"
    ec2        = "http://localhost:5000"
    iam        = "http://localhost:5000"
    s3         = "http://localhost:5000"
    sts        = "http://localhost:5000"
  }
}
