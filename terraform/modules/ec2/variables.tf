variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for security group rules"
  type        = string
}

variable "private_subnet_id" {
  description = "Subnet ID for EC2 instance (can be public or private)"
  type        = string
}

variable "assign_public_ip" {
  description = "Assign a public IP to the EC2 instance"
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "ami_id" {
  description = "AMI ID for EC2 instance"
  type        = string
}

variable "enable_ebs_encryption" {
  description = "Enable EBS encryption"
  type        = bool
  default     = true
}

variable "ebs_kms_key_id" {
  description = "KMS key ID for EBS encryption"
  type        = string
  default     = null
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH"
  type        = list(string)
  default     = []
}

variable "enable_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "cloudfront_secret_header_name" {
  description = "CloudFront secret header name for origin verification"
  type        = string
  default     = ""
}

variable "cloudfront_secret_header_value" {
  description = "CloudFront secret header value for origin verification"
  type        = string
  default     = ""
  sensitive   = true
}

variable "cloudfront_secret_arn" {
  description = "ARN of Secrets Manager secret containing CloudFront header"
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "GitHub repository in format 'owner/repo' to fetch logo from"
  type        = string
  default     = ""
}

variable "github_branch" {
  description = "GitHub branch to fetch logo from"
  type        = string
  default     = "main"
}
