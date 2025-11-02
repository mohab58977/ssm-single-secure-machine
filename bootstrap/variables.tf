variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "ssm-secure-machine"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.state_bucket_name))
    error_message = "Bucket name must be lowercase, alphanumeric, and hyphens only."
  }
}

variable "administrator_role_arns" {
  description = "List of administrator role ARNs that can decrypt and access the state bucket"
  type        = list(string)
  
  validation {
    condition     = length(var.administrator_role_arns) > 0
    error_message = "At least one administrator role ARN must be provided."
  }
}

variable "terraform_role_arns" {
  description = "List of Terraform execution role ARNs (e.g., GitHub Actions OIDC role)"
  type        = list(string)
  
  validation {
    condition     = length(var.terraform_role_arns) > 0
    error_message = "At least one Terraform role ARN must be provided."
  }
}
