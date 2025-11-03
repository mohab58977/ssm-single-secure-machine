output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = module.vpc.public_subnet_ids
}

output "nat_gateway_ips" {
  description = "Elastic IPs of NAT Gateways"
  value       = module.vpc.nat_gateway_ips
}

output "instance_id" {
  description = "ID of the EC2 instance"
  value       = module.ec2.instance_id
}

output "instance_private_ip" {
  description = "Private IP of the EC2 instance"
  value       = module.ec2.instance_private_ip
}

output "instance_role_arn" {
  description = "ARN of the EC2 instance IAM role"
  value       = module.ec2.instance_role_arn
}

output "security_group_id" {
  description = "ID of the instance security group"
  value       = module.ec2.security_group_id
}

output "ssm_connection_command" {
  description = "Command to connect to instance via SSM"
  value       = "aws ssm start-session --target ${module.ec2.instance_id} --region ${var.aws_region}"
}

output "ami_id" {
  description = "AMI ID used for the instance"
  value       = data.aws_ami.ubuntu.id
}

output "ami_name" {
  description = "AMI name"
  value       = data.aws_ami.ubuntu.name
}

output "elastic_ip" {
  description = "Elastic IP address of the EC2 instance"
  value       = aws_eip.ec2.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS of the EC2 instance"
  value       = aws_eip.ec2.public_dns
}

output "cloudfront_url" {
  description = "CloudFront distribution URL (HTTPS)"
  value       = module.cloudfront.cloudfront_url
}

output "cloudfront_domain" {
  description = "CloudFront domain name"
  value       = module.cloudfront.cloudfront_domain_name
}

output "image_url" {
  description = "Public URL to access the hosted image"
  value       = "${module.cloudfront.cloudfront_url}/logo.png"
}

output "secrets_manager_arn" {
  description = "ARN of Secrets Manager secret for CloudFront verification"
  value       = module.cloudfront.secrets_manager_arn
}
