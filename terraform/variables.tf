variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "ssm-secure-machine"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_retention" {
  description = "VPC Flow Logs retention in days"
  type        = number
  default     = 30
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.flow_logs_retention)
    error_message = "Flow logs retention must be a valid CloudWatch Logs retention value."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "enable_ebs_encryption" {
  description = "Enable EBS encryption"
  type        = bool
  default     = true
}

variable "ebs_kms_key_id" {
  description = "KMS key ID for EBS encryption (uses AWS managed key if not specified)"
  type        = string
  default     = null
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH (only use for emergency access)"
  type        = list(string)
  default     = []
}

variable "enable_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "github_repo" {
  description = "GitHub repository in format 'owner/repo' (e.g., 'username/ssm-single-secure-machine')"
  type        = string
  default     = ""
}

variable "github_branch" {
  description = "GitHub branch to fetch logo from"
  type        = string
  default     = "main"
}

variable "enable_cloudfront" {
  description = "Whether to create CloudFront distribution (set false if account not verified)"
  type        = bool
  default     = true
}
