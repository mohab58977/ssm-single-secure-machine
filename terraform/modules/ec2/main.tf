# Security Group for EC2 Instance
resource "aws_security_group" "instance" {
  name_prefix = "${var.project_name}-${var.environment}-instance-"
  description = "Security group for EC2 instance"
  vpc_id      = var.vpc_id
  
  # Egress: Allow HTTPS to VPC endpoints for SSM
  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  # Egress: Allow HTTPS to internet for package updates (NAT Gateway)
  #tfsec:ignore:aws-ec2-no-public-egress-sgr
  egress {
    description = "HTTPS for package updates via NAT"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Required for dnf updates, routed via NAT Gateway
  }
  
  # Egress: Allow HTTP to internet for package updates (NAT Gateway)
  #tfsec:ignore:aws-ec2-no-public-egress-sgr
  egress {
    description = "HTTP for package updates via NAT"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Required for dnf updates, routed via NAT Gateway
  }
  
  # Egress: Allow DNS to VPC DNS resolver
  egress {
    description = "DNS queries to VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  
  # Optional SSH access (only if CIDRs provided - for emergency use)
  dynamic "ingress" {
    for_each = length(var.allowed_ssh_cidrs) > 0 ? [1] : []
    content {
      description = "SSH from allowed CIDRs (emergency only)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_ssh_cidrs
    }
  }
  
  tags = {
    Name = "${var.project_name}-${var.environment}-instance-sg"
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# IAM Role for EC2 Instance
resource "aws_iam_role" "instance" {
  name_prefix = "${var.project_name}-${var.environment}-instance-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-${var.environment}-instance-role"
  }
}

# Attach SSM managed policy for Systems Manager access
resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach CloudWatch Agent policy
resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Custom IAM policy for additional security logging and secrets access
resource "aws_iam_role_policy" "instance_policy" {
  name_prefix = "${var.project_name}-${var.environment}-instance-"
  role        = aws_iam_role.instance.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/${var.project_name}-${var.environment}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = var.cloudfront_secret_arn != "" ? var.cloudfront_secret_arn : "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:*"
      }
    ]
  })
}

# Instance Profile
resource "aws_iam_instance_profile" "instance" {
  name_prefix = "${var.project_name}-${var.environment}-instance-"
  role        = aws_iam_role.instance.name
  
  tags = {
    Name = "${var.project_name}-${var.environment}-instance-profile"
  }
}

# KMS Key for EBS Encryption
resource "aws_kms_key" "ebs" {
  count                   = var.enable_ebs_encryption && var.ebs_kms_key_id == null ? 1 : 0
  description             = "KMS key for EBS encryption"
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
        Sid    = "Allow EC2 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
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
    Name = "${var.project_name}-${var.environment}-ebs-kms"
  }
}

resource "aws_kms_alias" "ebs" {
  count         = var.enable_ebs_encryption && var.ebs_kms_key_id == null ? 1 : 0
  name          = "alias/${var.project_name}-${var.environment}-ebs"
  target_key_id = aws_kms_key.ebs[0].key_id
}

# EC2 Instance
resource "aws_instance" "main" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  
  # Security: IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  # Security: Enable monitoring
  monitoring = var.enable_monitoring
  
  # CKV_AWS_135: Enable EBS optimization
  ebs_optimized = true
  
  # Security: EBS encryption
  root_block_device {
    encrypted   = var.enable_ebs_encryption
    kms_key_id  = var.enable_ebs_encryption ? (var.ebs_kms_key_id != null ? var.ebs_kms_key_id : aws_kms_key.ebs[0].arn) : null
    volume_type = "gp3"
    volume_size = 30  # 30GB minimum for CIS hardened AMI snapshots
    iops        = 3000  # gp3 baseline
    throughput  = 125   # gp3 baseline MB/s
    
    delete_on_termination = true
    
    tags = {
      Name = "${var.project_name}-${var.environment}-root-volume"
    }
  }
  
  # User data for initial hardening and web server setup
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    project_name          = var.project_name
    environment           = var.environment
    region                = data.aws_region.current.name
    cloudfront_secret_arn = var.cloudfront_secret_arn
    github_repo           = var.github_repo
    github_branch         = var.github_branch
  }))
  
  # Prevent accidental termination in production
  disable_api_termination = var.environment == "prod" ? true : false
  
  # Enable detailed monitoring
  credit_specification {
    cpu_credits = "standard"
  }
  
  tags = {
    Name   = "${var.project_name}-${var.environment}-instance"
    Backup = "true"
  }
  
  lifecycle {
    ignore_changes = [
      ami,  # Prevent replacement on AMI updates
      user_data
    ]
  }
}

# CloudWatch Log Group for instance logs
resource "aws_cloudwatch_log_group" "instance" {
  name              = "/aws/ec2/${var.project_name}-${var.environment}"
  retention_in_days = 365  # CKV_AWS_338: At least 1 year retention
  kms_key_id        = aws_kms_key.logs.arn
  
  tags = {
    Name = "${var.project_name}-${var.environment}-instance-logs"
  }
}

# KMS Key for CloudWatch Logs encryption
resource "aws_kms_key" "logs" {
  description             = "KMS key for CloudWatch Logs encryption"
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
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-${var.environment}-logs-kms"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.project_name}-${var.environment}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${var.project_name}-${var.environment}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EC2 CPU utilization"
  
  dimensions = {
    InstanceId = aws_instance.main.id
  }
  
  tags = {
    Name = "${var.project_name}-${var.environment}-cpu-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "status_check_failed" {
  alarm_name          = "${var.project_name}-${var.environment}-status-check-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "This metric monitors EC2 status checks"
  
  dimensions = {
    InstanceId = aws_instance.main.id
  }
  
  tags = {
    Name = "${var.project_name}-${var.environment}-status-check-alarm"
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
