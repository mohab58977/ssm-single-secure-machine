#!/bin/bash
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting instance hardening for ${project_name}-${environment}"

# Update all packages
dnf update -y

# Install security tools and SSM agent
dnf install -y \
    fail2ban \
    aide \
    audit \
    amazon-cloudwatch-agent \
    amazon-ssm-agent

# Ensure SSM agent is enabled and started
echo "Ensuring SSM agent is running..."
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
systemctl status amazon-ssm-agent --no-pager

# Configure automatic security updates
dnf install -y dnf-automatic
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer

# Harden SSH (even though we prefer SSM)
if [ -f /etc/ssh/sshd_config ]; then
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Apply hardening
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    
    # Add additional hardening
    cat >> /etc/ssh/sshd_config <<EOF

# Additional hardening
Protocol 2
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
EOF
    
    systemctl restart sshd || true
fi

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Initialize AIDE (File Integrity Monitoring)
echo "Initializing AIDE database..."
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Configure daily AIDE checks
cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
/usr/sbin/aide --check | tee /var/log/aide/aide-check-$(date +%Y%m%d).log
EOF
chmod +x /etc/cron.daily/aide-check

# Enable and configure auditd
systemctl enable auditd
systemctl start auditd

# Add custom audit rules for security monitoring
cat >> /etc/audit/rules.d/custom.rules <<EOF
# Monitor authentication events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# Monitor network changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_files
-w /etc/resolv.conf -p wa -k network_files

# Monitor file permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes
EOF

# Reload audit rules
augenrules --load

# Set up CloudWatch agent for logs
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/ec2/${project_name}-${environment}",
            "log_stream_name": "{instance_id}/messages"
          },
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/aws/ec2/${project_name}-${environment}",
            "log_stream_name": "{instance_id}/secure"
          },
          {
            "file_path": "/var/log/audit/audit.log",
            "log_group_name": "/aws/ec2/${project_name}-${environment}",
            "log_stream_name": "{instance_id}/audit"
          }
        ]
      }
    }
  },
  "metrics": {
    "namespace": "${project_name}/${environment}",
    "metrics_collected": {
      "mem": {
        "measurement": [
          {
            "name": "mem_used_percent",
            "rename": "MemoryUtilization",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60
      },
      "disk": {
        "measurement": [
          {
            "name": "used_percent",
            "rename": "DiskUtilization",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "/"
        ]
      }
    }
  }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -s \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

# Configure firewall (firewalld)
systemctl enable firewalld
systemctl start firewalld

# Only allow SSH if needed (we prefer SSM)
firewall-cmd --permanent --remove-service=ssh || true
firewall-cmd --permanent --remove-service=http || true
firewall-cmd --reload

# Disable unnecessary services
systemctl disable postfix || true
systemctl stop postfix || true

# Set kernel security parameters
cat >> /etc/sysctl.d/99-security.conf <<EOF
# IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore Broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Enable bad error message protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf

# Set file permissions
chmod 600 /etc/ssh/sshd_config
chmod 700 /root
chmod 600 /etc/crontab
chmod 600 /etc/at.deny || true

# Ensure SSM agent is running
echo "Configuring SSM agent..."
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Verify SSM agent status
SSM_STATUS=$(systemctl is-active amazon-ssm-agent)
echo "SSM agent status: $SSM_STATUS"

# Create a marker file to indicate hardening is complete
echo "Instance hardening completed at $(date)" > /var/log/hardening-complete.log
echo "SSM agent status: $SSM_STATUS" >> /var/log/hardening-complete.log

echo "User data script completed successfully"
