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

# Latest Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"]  # Amazon

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
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
  private_subnet_id     = module.vpc.public_subnet_ids[0]
  instance_type         = var.instance_type
  ami_id                = data.aws_ami.al2023.id
  enable_ebs_encryption = var.enable_ebs_encryption
  ebs_kms_key_id        = var.ebs_kms_key_id
  allowed_ssh_cidrs     = var.allowed_ssh_cidrs
  enable_monitoring     = var.enable_monitoring
  assign_public_ip      = true
  
  # CloudFront security (optional)
  cloudfront_secret_header_name  = var.enable_cloudfront ? module.cloudfront[0].secret_header_name : ""
  cloudfront_secret_header_value = var.enable_cloudfront ? module.cloudfront[0].secret_header_value : ""
  cloudfront_secret_arn          = var.enable_cloudfront ? module.cloudfront[0].secrets_manager_arn : ""
  
  # GitHub repository for logo
  github_repo   = var.github_repo
  github_branch = var.github_branch
}

# Elastic IP for EC2 (only when CloudFront is enabled)
resource "aws_eip" "ec2" {
  count    = var.enable_cloudfront ? 1 : 0
  domain   = "vpc"
  instance = module.ec2.instance_id

  tags = {
    Name = "${var.project_name}-${var.environment}-eip"
  }

  depends_on = [module.ec2]
}

# CloudFront Distribution Module (optional)
module "cloudfront" {
  count  = var.enable_cloudfront ? 1 : 0
  source = "./modules/cloudfront"
  
  project_name   = var.project_name
  environment    = var.environment
  ec2_public_dns = aws_eip.ec2[0].public_dns
  enable_logging = false  # Set to true if you want access logs (requires S3 bucket)
}
