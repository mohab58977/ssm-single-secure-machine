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

variable "waf_web_acl_id" {
  description = "WAF Web ACL ID to associate with CloudFront (optional)"
  type        = string
  default     = ""
}

variable "geo_restriction_locations" {
  description = "List of country codes to allow access from (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = ["US", "CA", "GB", "DE", "FR", "ES", "IT", "NL", "BE", "SE", "NO", "DK", "FI", "IE", "AT", "CH", "AU", "NZ", "JP", "SG"]
}
