# Terraform State Backend Bootstrap

This directory contains Terraform configuration to create a **highly secure S3 backend** for storing Terraform state with the following security features:

## 🔒 Security Features

### S3 Bucket
- **Versioning enabled** - Provides state locking via S3 (no DynamoDB needed)
- **KMS encryption** - All objects encrypted at rest
- **Access logging** - All access logged to separate bucket
- **Public access blocked** - No public access allowed
- **Lifecycle policies** - Old versions archived/expired automatically
- **Bucket policy** - Only administrators and Terraform roles can access

### KMS Encryption
- **Automatic key rotation** - Keys rotated annually
- **Restricted access** - Only administrators can decrypt
- **Terraform role** - Limited to encrypt/decrypt via S3 only
- **Audit trail** - All key usage logged via CloudTrail

### Access Control
- **Administrator roles** - Full access including decryption
- **Terraform roles** - Can read/write state but limited KMS access
- **Deny all others** - Explicit deny for any other principals
- **SSL required** - All requests must use HTTPS
- **Enforce encryption** - Only KMS-encrypted objects allowed

## 📋 Prerequisites

1. AWS account with administrator access
2. AWS CLI configured with admin credentials
3. Terraform >= 1.6.0 installed
4. IAM roles created:
   - Administrator role(s) for managing the state
   - Terraform execution role(s) for GitHub Actions

## 🚀 Quick Start

### Option 1: Using GitHub Actions (Recommended)

1. **Add GitHub Secret**: `AWS_ADMIN_ROLE_ARN` (admin role with permissions to create S3/KMS)

2. **Run Bootstrap Workflow**:
   - Go to Actions → "Bootstrap Terraform Backend"
   - Click "Run workflow"
   - Fill in:
     - Action: `plan` (first) then `apply`
     - State bucket name: `terr-backend-69`
     - Administrator role ARNs: `arn:aws:iam::123456789012:role/AdminRole`
     - Terraform role ARNs: `arn:aws:iam::123456789012:role/GitHubActionsRole`

3. **Review Plan**: Check the plan output carefully

4. **Apply**: Run again with action `apply`

### Option 2: Local Execution

1. **Copy example variables**:
   ```bash
   cd bootstrap
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Edit `terraform.tfvars`**:
   ```hcl
   state_bucket_name = "terr-backend-69"
   
   administrator_role_arns = [
     "arn:aws:iam::123456789012:role/AdminRole"
   ]
   
   terraform_role_arns = [
     "arn:aws:iam::123456789012:role/GitHubActionsRole"
   ]
   ```

3. **Initialize and apply**:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

4. **Save outputs**:
   ```bash
   terraform output -raw terragrunt_backend_config
   ```

## 🔑 Getting Role ARNs

### Administrator Role ARN
```bash
# If you're using your root account or admin user
aws sts get-caller-identity

# If using a role
aws iam get-role --role-name AdminRole --query 'Role.Arn' --output text
```

### Terraform Role ARN (GitHub Actions OIDC)
```bash
# Get the GitHub Actions role ARN
aws iam get-role --role-name GitHubActionsRole --query 'Role.Arn' --output text
```

## 📝 Update Main Terraform Configuration

After bootstrap completes, update your main Terraform configuration:

### Update `terraform/terragrunt.hcl`

Replace the `remote_state` block with the output from bootstrap:

```hcl
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
    kms_key_id     = "YOUR-KMS-KEY-ARN-FROM-OUTPUT"
    
    # Remove DynamoDB table configuration
    # dynamodb_table = "..."  # NOT NEEDED - S3 versioning provides locking
  }
}
```

## 🔐 Security Best Practices

### 1. Restrict Administrator Access
Only grant administrator role ARNs to:
- Your personal admin role/user
- Break-glass emergency access roles
- CI/CD service accounts (if absolutely necessary)

### 2. Audit Access Regularly
Check access logs in the logs bucket:
```bash
aws s3 ls s3://YOUR-BUCKET-NAME-logs/state-access-logs/
```

### 3. Enable CloudTrail
Monitor KMS key usage:
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=YOUR-KMS-KEY-ID \
  --max-results 50
```

### 4. Backup State Files
S3 versioning is enabled, but consider additional backups:
```bash
# Download current state
aws s3 cp s3://YOUR-BUCKET-NAME/dev/terraform.tfstate ./backup/

# Verify encryption
aws s3api head-object \
  --bucket YOUR-BUCKET-NAME \
  --key dev/terraform.tfstate \
  --query 'ServerSideEncryption'
```

### 5. Rotate Credentials
- KMS keys rotate automatically annually
- Rotate admin credentials regularly
- Use temporary credentials where possible (OIDC)

## 🛡️ How S3 Versioning Provides Locking

Unlike DynamoDB locking, S3 versioning provides locking through:

1. **Version IDs**: Each state write creates a new version
2. **Optimistic Locking**: Terraform checks version before write
3. **Conflict Detection**: Multiple writes create multiple versions
4. **Manual Resolution**: Conflicts require manual merge (safer)

**Note**: S3 versioning is less automated than DynamoDB but:
- ✅ Simpler infrastructure (one less service)
- ✅ Better audit trail (all versions preserved)
- ✅ Lower cost (no DynamoDB charges)
- ⚠️ Requires manual conflict resolution (rare in CI/CD)

## 🗑️ Destroying the Backend

**WARNING**: This will delete all Terraform state history!

1. **Backup all state files** from all environments
2. **Remove state references** from all Terraform configs
3. **Run destroy**:
   ```bash
   terraform destroy
   ```

Or via GitHub Actions with action: `destroy`

## 📊 Cost Estimate

- **S3 Standard**: ~$0.023/GB/month
- **S3 Versioning**: Storage for all versions (auto-archived)
- **KMS Key**: $1/month + $0.03/10k requests
- **S3 Requests**: ~$0.005/1k requests
- **Data Transfer**: First 1 GB free, then $0.09/GB

**Typical cost**: $1-5/month for small teams

## 🆘 Troubleshooting

### Access Denied when reading state
```bash
# Check your assumed role
aws sts get-caller-identity

# Verify role is in the allowed list
aws s3api get-bucket-policy --bucket YOUR-BUCKET-NAME

# Check KMS key permissions
aws kms get-key-policy --key-id YOUR-KMS-KEY-ID --policy-name default
```

### State conflicts
```bash
# List all versions
aws s3api list-object-versions \
  --bucket YOUR-BUCKET-NAME \
  --prefix dev/terraform.tfstate

# Download specific version
aws s3api get-object \
  --bucket YOUR-BUCKET-NAME \
  --key dev/terraform.tfstate \
  --version-id VERSION-ID \
  ./state-backup.tfstate
```

## 📚 Additional Resources

- [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
- [KMS Key Policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html)
- [S3 Bucket Policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [Terraform S3 Backend](https://developer.hashicorp.com/terraform/language/settings/backends/s3)
