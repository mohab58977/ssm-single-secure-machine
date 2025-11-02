output "state_bucket_name" {
  description = "Name of the Terraform state bucket"
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the Terraform state bucket"
  value       = aws_s3_bucket.terraform_state.arn
}

output "state_bucket_region" {
  description = "Region of the Terraform state bucket"
  value       = aws_s3_bucket.terraform_state.region
}

output "kms_key_id" {
  description = "ID of the KMS key for state encryption"
  value       = aws_kms_key.terraform_state.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key for state encryption"
  value       = aws_kms_key.terraform_state.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key"
  value       = aws_kms_alias.terraform_state.name
}

output "logs_bucket_name" {
  description = "Name of the logs bucket"
  value       = aws_s3_bucket.terraform_state_logs.id
}

output "backend_config" {
  description = "Backend configuration for main Terraform code"
  value = {
    bucket         = aws_s3_bucket.terraform_state.id
    region         = var.aws_region
    encrypt        = true
    kms_key_id     = aws_kms_key.terraform_state.arn
    use_lockfile   = true
  }
}

output "terragrunt_backend_config" {
  description = "Instructions for Terragrunt backend configuration"
  value = <<-EOT
    Add this to your terragrunt.hcl:
    
    remote_state {
      backend = "s3"
      config = {
        bucket         = "${aws_s3_bucket.terraform_state.id}"
        key            = "$${path_relative_to_include()}/terraform.tfstate"
        region         = "${var.aws_region}"
        encrypt        = true
        kms_key_id     = "${aws_kms_key.terraform_state.arn}"
      }
    }
  EOT
}
