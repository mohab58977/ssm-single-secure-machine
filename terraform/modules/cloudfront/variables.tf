variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "ec2_public_dns" {
  description = "Public DNS name of the EC2 instance"
  type        = string
}

variable "enable_logging" {
  description = "Enable CloudFront access logging"
  type        = bool
  default     = false
}

variable "logging_bucket" {
  description = "S3 bucket for CloudFront logs (must end with .s3.amazonaws.com)"
  type        = string
  default     = ""
}
