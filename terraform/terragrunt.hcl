locals {
  aws_region     = "us-east-1"
  account_id     = get_aws_account_id()
  environment    = get_env("ENVIRONMENT", "dev")
  project_name   = "ssm-secure-machine"
  
  common_tags = {
    Project     = local.project_name
    Environment = local.environment
    ManagedBy   = "Terragrunt"
    Repository  = "ssm-single-secure-machine"
  }
}

# Generate provider configuration
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  region = "${local.aws_region}"
  
  default_tags {
    tags = ${jsonencode(local.common_tags)}
  }
  
  # Security best practices
  skip_metadata_api_check     = false
  skip_region_validation      = false
  skip_credentials_validation = false
  skip_requesting_account_id  = false
}
EOF
}

# Configure remote state with S3 versioning-based locking (no DynamoDB)
remote_state {
  backend = "s3"
  
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  
  config = {
    bucket         = "terr-backend-69"
    key            = "${local.environment}/${path_relative_to_include()}/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    # KMS key ID will be set after bootstrap
    # kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"
    
    # S3 bucket security
    s3_bucket_tags = merge(
      local.common_tags,
      {
        Name = "terr-backend-69"
        Type = "TerraformState"
      }
    )
    
    # S3 versioning provides locking (no DynamoDB needed)
  }
}

# Terraform settings
terraform {
  # Require minimum Terraform version
  extra_arguments "common_vars" {
    commands = get_terraform_commands_that_need_vars()
    
    arguments = [
      "-var", "environment=${local.environment}",
      "-var", "aws_region=${local.aws_region}",
      "-var", "project_name=${local.project_name}",
    ]
  }
  
  # Format before commands
  before_hook "terraform_fmt" {
    commands = ["apply", "plan"]
    execute  = ["terraform", "fmt", "-recursive"]
  }
  
  # Security validation
  after_hook "validate" {
    commands = ["apply", "plan"]
    execute  = ["terraform", "validate"]
  }
}

# Retry configuration for transient errors
retryable_errors = [
  "(?s).*Error.*429.*",
  "(?s).*Error.*RequestLimitExceeded.*",
  "(?s).*Error.*TooManyRequestsException.*",
  "(?s).*Error.*Throttling.*",
  "(?s).*connection reset by peer.*",
]

retry_max_attempts       = 3
retry_sleep_interval_sec = 5
