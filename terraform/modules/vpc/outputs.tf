output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "nat_gateway_ips" {
  description = "Elastic IPs of NAT Gateways"
  value       = aws_eip.nat[*].public_ip
}

output "vpc_endpoint_ssm_id" {
  description = "ID of SSM VPC Endpoint"
  value       = aws_vpc_endpoint.ssm.id
}

output "vpc_endpoint_s3_id" {
  description = "ID of S3 VPC Endpoint"
  value       = aws_vpc_endpoint.s3.id
}
