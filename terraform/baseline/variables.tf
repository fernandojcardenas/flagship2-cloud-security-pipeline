variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix used for every resource, so they're easy to identify and tear down."
  type        = string
  default     = "flagship2-baseline"
}
