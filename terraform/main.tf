terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.82"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  
  backend "s3" {
    bucket         = "terr-backend-69"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    # KMS key ARN - update this after bootstrap
    # kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Repository  = "ssm-single-secure-machine"
    }
  }
  
  # Security best practices
  skip_metadata_api_check     = false
  skip_region_validation      = false
  skip_credentials_validation = false
  skip_requesting_account_id  = false
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Latest Ubuntu LTS AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-amd64-server-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"
  
  project_name        = var.project_name
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  availability_zones  = slice(data.aws_availability_zones.available.names, 0, 2)
  enable_flow_logs    = var.enable_flow_logs
  flow_logs_retention = var.flow_logs_retention
}

# EC2 Instance Module
module "ec2" {
  source = "./modules/ec2"
  
  project_name          = var.project_name
  environment           = var.environment
  vpc_id                = module.vpc.vpc_id
  vpc_cidr              = var.vpc_cidr
  private_subnet_id     = module.vpc.private_subnet_ids[0]
  instance_type         = var.instance_type
  ami_id                = data.aws_ami.ubuntu.id
  enable_ebs_encryption = var.enable_ebs_encryption
  ebs_kms_key_id        = var.ebs_kms_key_id
  allowed_ssh_cidrs     = var.allowed_ssh_cidrs
  enable_monitoring     = var.enable_monitoring
  
  # CloudFront security
  cloudfront_secret_header_name  = module.cloudfront.secret_header_name
  cloudfront_secret_header_value = module.cloudfront.secret_header_value
  cloudfront_secret_arn          = module.cloudfront.secrets_manager_arn
  
  # GitHub repository for logo
  github_repo   = var.github_repo
  github_branch = var.github_branch
}

# Elastic IP for EC2 (needed for CloudFront origin)
resource "aws_eip" "ec2" {
  domain   = "vpc"
  instance = module.ec2.instance_id

  tags = {
    Name = "${var.project_name}-${var.environment}-eip"
  }

  depends_on = [module.ec2]
}

# CloudFront Distribution Module
module "cloudfront" {
  source = "./modules/cloudfront"
  
  project_name   = var.project_name
  environment    = var.environment
  ec2_public_dns = aws_eip.ec2.public_dns
  enable_logging = false  # Set to true if you want access logs (requires S3 bucket)
}
