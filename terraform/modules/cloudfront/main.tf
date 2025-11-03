# Generate a random secret for CloudFront to EC2 communication
resource "random_password" "cloudfront_secret" {
  length  = 32
  special = true
}

# KMS Key for Secrets Manager encryption
resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-secrets-kms"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.project_name}-${var.environment}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# Store secret in AWS Secrets Manager
#checkov:skip=CKV2_AWS_57:Automatic rotation not needed - secret is randomly generated and only used internally
resource "aws_secretsmanager_secret" "cloudfront_secret" {
  name_prefix             = "${var.project_name}-${var.environment}-cf-secret-"
  description             = "Secret header for CloudFront to EC2 communication"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.secrets.arn

  tags = {
    Name = "${var.project_name}-${var.environment}-cloudfront-secret"
  }
}

resource "aws_secretsmanager_secret_version" "cloudfront_secret" {
  secret_id = aws_secretsmanager_secret.cloudfront_secret.id
  secret_string = jsonencode({
    header_name  = "X-Custom-Origin-Verify"
    header_value = random_password.cloudfront_secret.result
  })
}

# CloudFront Origin Access Identity (legacy but free)
resource "aws_cloudfront_origin_access_identity" "main" {
  comment = "OAI for ${var.project_name}-${var.environment}"
}

# CloudFront Distribution
#checkov:skip=CKV_AWS_310:Origin failover requires multiple origins/instances - not needed for single instance setup
#checkov:skip=CKV_AWS_68:WAF is optional and adds cost - can be enabled via waf_web_acl_id variable
#checkov:skip=CKV2_AWS_47:WAF with Log4j rules requires WAF to be enabled first
#checkov:skip=CKV2_AWS_42:Custom SSL certificate requires domain ownership - using CloudFront default for demo
#checkov:skip=CKV_AWS_174:TLS 1.2 is configured but check requires ACM certificate for custom domain
resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.project_name} ${var.environment} - Secure image hosting"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"  # US, Canada, Europe only - cheapest

  origin {
    domain_name = var.ec2_public_dns
    origin_id   = "ec2-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"  # EC2 internal HTTP, CloudFront handles HTTPS
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 30
      origin_keepalive_timeout = 5
    }

    # Custom header to verify requests come from CloudFront
    custom_header {
      name  = "X-Custom-Origin-Verify"
      value = random_password.cloudfront_secret.result
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ec2-origin"

    forwarded_values {
      query_string = false
      headers      = ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"]

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400      # 1 day
    max_ttl                = 31536000   # 1 year
    compress               = true

    # Security headers
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # Cache behavior for images - longer TTL
  ordered_cache_behavior {
    path_pattern     = "*.png"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ec2-origin"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 86400
    default_ttl            = 604800     # 7 days
    max_ttl                = 31536000   # 1 year
    compress               = true

    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  restrictions {
    geo_restriction {
      restriction_type = length(var.geo_restriction_locations) > 0 ? "whitelist" : "none"
      locations        = length(var.geo_restriction_locations) > 0 ? var.geo_restriction_locations : []
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  # WAF Web ACL Association
  web_acl_id = var.waf_web_acl_id != "" ? var.waf_web_acl_id : null

  # Logging configuration (optional, uses S3)
  dynamic "logging_config" {
    for_each = var.enable_logging ? [1] : []
    content {
      bucket          = var.logging_bucket
      include_cookies = false
      prefix          = "cloudfront/"
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-cloudfront"
  }
}

# CloudFront Response Headers Policy - Maximum Security
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "${var.project_name}-${var.environment}-security-headers"
  comment = "Security headers policy for image hosting"

  security_headers_config {
    # HSTS - Force HTTPS
    strict_transport_security {
      access_control_max_age_sec = 63072000  # 2 years
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    # Prevent MIME sniffing
    content_type_options {
      override = true
    }

    # Prevent clickjacking
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    # XSS Protection
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    # Referrer Policy
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    # Content Security Policy
    content_security_policy {
      content_security_policy = "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'none';"
      override                = true
    }
  }

  # Additional custom headers (non-security headers only)
  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
      override = true
    }

    items {
      header   = "X-Permitted-Cross-Domain-Policies"
      value    = "none"
      override = true
    }
  }

  # CORS configuration
  cors_config {
    access_control_allow_credentials = false

    access_control_allow_headers {
      items = ["*"]
    }

    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }

    access_control_allow_origins {
      items = ["*"]
    }

    access_control_max_age_sec = 600
    origin_override            = false
  }
}

# Data sources
data "aws_caller_identity" "current" {}

# CloudWatch alarm for high error rate
resource "aws_cloudwatch_metric_alarm" "cloudfront_error_rate" {
  alarm_name          = "${var.project_name}-${var.environment}-cloudfront-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "5"
  alarm_description   = "CloudFront 5xx error rate is too high"

  dimensions = {
    DistributionId = aws_cloudfront_distribution.main.id
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-cloudfront-error-alarm"
  }
}
