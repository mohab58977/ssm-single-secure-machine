terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.82"
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  
  filter {
    name   = "architecture"
    values = ["x86_64"]
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
  private_subnet_id     = module.vpc.private_subnet_ids[0]
  instance_type         = var.instance_type
  ami_id                = data.aws_ami.amazon_linux_2023.id
  enable_ebs_encryption = var.enable_ebs_encryption
  ebs_kms_key_id        = var.ebs_kms_key_id
  allowed_ssh_cidrs     = var.allowed_ssh_cidrs
  enable_monitoring     = var.enable_monitoring
}
