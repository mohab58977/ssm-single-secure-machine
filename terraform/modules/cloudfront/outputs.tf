output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.main.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.main.id
}

output "cloudfront_arn" {
  description = "CloudFront distribution ARN"
  value       = aws_cloudfront_distribution.main.arn
}

output "cloudfront_url" {
  description = "Full HTTPS URL to access the distribution"
  value       = "https://${aws_cloudfront_distribution.main.domain_name}"
}

output "secret_header_name" {
  description = "Name of the custom header for origin verification"
  value       = "X-Custom-Origin-Verify"
  sensitive   = true
}

output "secret_header_value" {
  description = "Value of the custom header for origin verification"
  value       = random_password.cloudfront_secret.result
  sensitive   = true
}

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret containing CloudFront header"
  value       = aws_secretsmanager_secret.cloudfront_secret.arn
}
