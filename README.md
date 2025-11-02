# SSM Single Secure Machine

A hardened AWS infrastructure deployment using Terraform, Terragrunt, and GitHub Actions with OIDC authentication. This project deploys a secure VPC with an EC2 instance accessible only via AWS Systems Manager (SSM).

## 🔐 Security Features

### Infrastructure Security
- **Private EC2 Instance**: No public IP, accessible only via SSM
- **IMDSv2 Enforced**: Instance metadata service v2 required
- **EBS Encryption**: All volumes encrypted with KMS
- **VPC Flow Logs**: Network traffic monitoring with KMS encryption
- **Network Segmentation**: Public and private subnets across multiple AZs
- **NAT Gateways**: High-availability outbound internet access
- **VPC Endpoints**: Private connectivity to AWS services (S3, SSM, EC2 Messages)
- **Network ACLs**: Additional network layer security
- **Security Groups**: Minimal ingress, controlled egress

### Instance Hardening
- **Automatic Security Updates**: Configured via dnf-automatic
- **File Integrity Monitoring**: AIDE for detecting unauthorized changes
- **Audit Logging**: auditd with custom rules
- **Fail2Ban**: Intrusion prevention
- **Hardened SSH**: Disabled by default, SSM preferred
- **Firewall**: firewalld with minimal rules
- **Kernel Hardening**: Secure sysctl parameters
- **CloudWatch Agent**: Centralized logging and monitoring

### Pipeline Security
- **OIDC Authentication**: No long-lived AWS credentials
- **Environment Protection**: Manual approval for apply/destroy
- **Security Scanning**: tfsec and Checkov integration
- **Least Privilege**: Minimal IAM permissions
- **State Encryption**: S3 backend with encryption and versioning
- **State Locking**: DynamoDB for concurrent access prevention

## 📋 Prerequisites

1. **AWS Account** with appropriate permissions
2. **GitHub Repository** with Actions enabled
3. **AWS OIDC Provider** configured in GitHub
4. **S3 Bucket** for Terraform state (auto-created by Terragrunt)
5. **DynamoDB Table** for state locking (auto-created by Terragrunt)

## 🚀 Setup Instructions

### 1. Configure AWS OIDC for GitHub Actions

Create an OIDC provider in AWS IAM:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 2. Create IAM Role for GitHub Actions

Create a role with trust policy for your repository:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/ssm-single-secure-machine:*"
        }
      }
    }
  ]
}
```

Attach necessary policies (adjust permissions as needed):
- `PowerUserAccess` (or create a more restrictive custom policy)
- Custom policy for IAM role creation

### 3. Configure GitHub Secrets

Add the following secrets to your GitHub repository:

- `AWS_ROLE_ARN`: The ARN of the IAM role created above

### 4. Configure GitHub Environments

Create environments in GitHub (Settings → Environments):

- **dev**: No protection rules (optional)
- **staging**: Require reviewers
- **prod**: Require reviewers + wait timer

### 5. Initialize Terraform State Backend

The first time you run, Terragrunt will create the S3 bucket and DynamoDB table for state management.

## 📦 Project Structure

```
.
├── .github/
│   └── workflows/
│       └── terraform.yml          # GitHub Actions workflow
├── terraform/
│   ├── main.tf                    # Root module
│   ├── variables.tf               # Input variables
│   ├── outputs.tf                 # Outputs
│   ├── terragrunt.hcl            # Terragrunt configuration
│   └── modules/
│       ├── vpc/                   # VPC module
│       │   ├── main.tf
│       │   ├── variables.tf
│       │   └── outputs.tf
│       └── ec2/                   # EC2 module
│           ├── main.tf
│           ├── variables.tf
│           ├── outputs.tf
│           └── user_data.sh       # Instance hardening script
└── README.md
```

## 🎯 Usage

### Deploy Infrastructure

1. Go to **Actions** tab in GitHub
2. Select **Terraform Infrastructure** workflow
3. Click **Run workflow**
4. Choose:
   - Action: `plan` (to preview changes)
   - Environment: `dev`, `staging`, or `prod`
5. Review the plan output
6. Run again with Action: `apply` to create resources

### Connect to Instance

After deployment, connect via SSM:

```bash
# Get instance ID from outputs
aws ssm start-session --target i-xxxxxxxxxxxxx --region us-east-1
```

Or use AWS Console → Systems Manager → Session Manager

### Destroy Infrastructure

1. Run workflow with Action: `destroy`
2. Approve in the environment settings
3. Resources will be removed

## 🔧 Customization

### Modify Variables

Edit `terraform/variables.tf` to change defaults:

```hcl
variable "vpc_cidr" {
  default = "10.0.0.0/16"  # Change VPC CIDR
}

variable "instance_type" {
  default = "t3.micro"      # Change instance size
}
```

### Add Additional Security

1. **Enable AWS GuardDuty**: Monitor for threats
2. **AWS Config**: Track configuration changes
3. **AWS Security Hub**: Centralized security findings
4. **AWS Inspector**: Vulnerability scanning
5. **VPC Traffic Mirroring**: Deep packet inspection
6. **AWS WAF**: If exposing web services

### Customize Hardening

Edit `terraform/modules/ec2/user_data.sh` to add:
- CIS Benchmark compliance
- Additional monitoring agents
- Custom security tools
- Application-specific hardening

## 📊 Monitoring

### CloudWatch Dashboards

View metrics in CloudWatch:
- CPU utilization alarms
- Status check alarms
- Custom memory and disk metrics
- Application logs

### VPC Flow Logs

Analyze network traffic:
```bash
aws logs filter-log-events \
  --log-group-name /aws/vpc/ssm-secure-machine-dev-flow-logs \
  --filter-pattern "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"
```

### Instance Logs

View instance logs:
```bash
aws logs tail /aws/ec2/ssm-secure-machine-dev --follow
```

## 🛡️ Security Best Practices

1. **Never commit secrets** to the repository
2. **Enable MFA** on AWS accounts
3. **Rotate credentials** regularly
4. **Review IAM policies** periodically
5. **Enable CloudTrail** for audit logging
6. **Use separate environments** for dev/staging/prod
7. **Enable AWS Organizations** for multi-account strategy
8. **Implement backup strategy** for critical data
9. **Test disaster recovery** procedures
10. **Keep dependencies updated** (Terraform, providers)

## 🔍 Security Scanning

The pipeline automatically runs:
- **tfsec**: Terraform static analysis
- **Checkov**: Policy-as-code security scanning

Fix any findings before deploying to production.

## 📝 Maintenance

### Update AMI

The instance uses Amazon Linux 2023 latest AMI:
```bash
# Update will pick latest AMI automatically
terraform plan
terraform apply
```

### Patch Management

Instances automatically apply security updates via dnf-automatic.

### State Management

- State is stored in S3 with versioning enabled
- Use state locking to prevent conflicts
- Regular state backups recommended

## 🆘 Troubleshooting

### Cannot connect via SSM

1. Check VPC endpoints are created
2. Verify instance has IAM role with SSM permissions
3. Ensure security groups allow outbound HTTPS
4. Check SSM agent is running: `systemctl status amazon-ssm-agent`

### Terraform State Lock

If state is locked:
```bash
# List locks
aws dynamodb get-item \
  --table-name ssm-secure-machine-terraform-locks \
  --key '{"LockID": {"S": "ssm-secure-machine-terraform-state/dev/terraform.tfstate"}}'

# Force unlock (use with caution)
terragrunt force-unlock LOCK_ID
```

### GitHub Actions Fails

1. Check AWS_ROLE_ARN secret is set correctly
2. Verify OIDC trust relationship
3. Check IAM role has sufficient permissions
4. Review CloudTrail for authorization errors

## 📚 Additional Resources

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Terraform Best Practices](https://www.terraform-best-practices.com/)
- [AWS Systems Manager](https://docs.aws.amazon.com/systems-manager/)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)

## 📄 License

This project is provided as-is for educational and production use.

## 🤝 Contributing

Contributions welcome! Please follow security best practices and test thoroughly.
