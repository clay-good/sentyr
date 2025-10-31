# Sentyr Usage Guide

Complete guide to using all features of Sentyr.

---

## Table of Contents

1. [Basic Scanning](#basic-scanning)
2. [Advanced Scanning](#advanced-scanning)
3. [Employee Lifecycle](#employee-lifecycle)
4. [Policy Management](#policy-management)
5. [Compliance Reporting](#compliance-reporting)
6. [Monitoring & Metrics](#monitoring--metrics)
7. [Multi-Domain Operations](#multi-domain-operations)
8. [Filtering & Search](#filtering--search)
9. [Batch Operations](#batch-operations)

---

## Basic Scanning

### Scan Files for External Sharing

```bash
# Scan all files
sentyr scan files

# Scan only externally shared files
sentyr scan files --external-only

# Scan only publicly shared files
sentyr scan files --public-only

# Scan with PII detection
sentyr scan files --check-pii

# Scan specific user
sentyr scan files --user user@example.com

# Export to CSV
sentyr scan files --output report.csv --format csv

# Export to JSON
sentyr scan files --output report.json --format json
```

### Scan Users

```bash
# Scan all users
sentyr scan users

# Find inactive users (no login in 90 days)
sentyr scan users --inactive-days 90

# Check 2FA status
sentyr scan users --check-2fa

# Export results
sentyr scan users --output users.csv
```

### Scan Shared Drives

```bash
# Scan all Shared Drives
sentyr scan shared-drives

# Scan with PII detection
sentyr scan shared-drives --check-pii

# Export results
sentyr scan shared-drives --output shared-drives.json
```

---

## Advanced Scanning

### OAuth App Auditing

```bash
# Audit all OAuth apps
sentyr scan oauth-apps

# Show only high-risk apps
sentyr scan oauth-apps --high-risk-only

# Export results
sentyr scan oauth-apps --output oauth-apps.csv
```

### Gmail Attachment Scanning

```bash
# Scan Gmail attachments
sentyr scan gmail

# Scan specific user
sentyr scan gmail --user user@example.com

# Scan date range
sentyr scan gmail --after 2024-01-01 --before 2024-12-31

# Check for PII
sentyr scan gmail --check-pii

# Export results
sentyr scan gmail --output gmail-scan.json
```

---

## Employee Lifecycle

### Offboard Employee

```bash
# Dry-run (default - no changes made)
sentyr offboard user@example.com

# Execute offboarding
sentyr offboard user@example.com --execute

# Transfer files to manager
sentyr offboard user@example.com --transfer-to manager@example.com --execute

# Revoke external shares
sentyr offboard user@example.com --revoke-external --execute

# Full offboarding
sentyr offboard user@example.com \
  --transfer-to manager@example.com \
  --revoke-external \
  --execute
```

### Bulk Offboarding

```bash
# Offboard multiple users from file
sentyr offboard --from-file users.txt --execute

# users.txt format:
# user1@example.com
# user2@example.com
# user3@example.com
```

---

## Policy Management

### Auto-Expire External Shares

```bash
# Dry-run (default)
sentyr policy expire-shares --days 30

# Execute with grace period
sentyr policy expire-shares --days 30 --grace-period 7 --execute

# Exempt specific domains
sentyr policy expire-shares \
  --days 30 \
  --exempt-domain partner.com \
  --execute

# Exempt specific users
sentyr policy expire-shares \
  --days 30 \
  --exempt-user external-relations@example.com \
  --execute
```

### List Active Policies

```bash
# Show all policies
sentyr policy list

# Show policy details
sentyr policy show auto-expire
```

---

## Compliance Reporting

### Generate Compliance Reports

```bash
# GDPR compliance report
sentyr compliance --framework gdpr --output gdpr-report.json

# HIPAA compliance report
sentyr compliance --framework hipaa --output hipaa-report.json

# SOC 2 compliance report
sentyr compliance --framework soc2 --output soc2-report.json

# All frameworks
sentyr compliance --framework all --output compliance-report.json
```

### Compliance Scoring

```bash
# Show compliance score
sentyr compliance --framework gdpr --show-score

# Show only high-severity issues
sentyr compliance --framework gdpr --severity high
```

---

## Monitoring & Metrics

### Health Checks

```bash
# Check system health
sentyr monitor health

# JSON output
sentyr monitor health --format json

# Check specific components
sentyr monitor health --check system
sentyr monitor health --check api
sentyr monitor health --check database
```

### Metrics

```bash
# Show all metrics
sentyr monitor metrics

# Prometheus format
sentyr monitor metrics --format prometheus

# JSON format
sentyr monitor metrics --format json

# Table format
sentyr monitor metrics --format table
```

### Performance Monitoring

```bash
# Show performance statistics
sentyr monitor performance

# Show specific operation
sentyr monitor performance --operation scan_files

# Show percentiles
sentyr monitor performance --percentiles 50,95,99
```

### System Information

```bash
# Show system info
sentyr monitor system

# Show CPU usage
sentyr monitor system --cpu

# Show memory usage
sentyr monitor system --memory

# Show disk usage
sentyr monitor system --disk
```

---

## Multi-Domain Operations

### Configure Multiple Domains

Edit `config.yaml`:

```yaml
# Multi-domain configuration
domains:
  - domain: "example.com"
    credentials_file: "example-sa.json"
    impersonate_user: "admin@example.com"
    enabled: true
    tags: ["production", "primary"]
  
  - domain: "subsidiary.com"
    credentials_file: "subsidiary-sa.json"
    impersonate_user: "admin@subsidiary.com"
    enabled: true
    tags: ["production", "subsidiary"]
  
  - domain: "dev.example.com"
    credentials_file: "dev-sa.json"
    impersonate_user: "admin@dev.example.com"
    enabled: false  # Disabled
    tags: ["development"]
```

### Scan Multiple Domains

```bash
# Scan all enabled domains
sentyr scan files --all-domains

# Scan specific domain
sentyr scan files --domain example.com

# Scan domains with specific tag
sentyr scan files --domain-tag production

# Parallel scanning (faster)
sentyr scan files --all-domains --parallel

# Sequential scanning (safer)
sentyr scan files --all-domains --sequential
```

---

## Filtering & Search

### Filter by Risk Score

```bash
# High risk only (score >= 75)
sentyr scan files --min-risk 75

# Medium risk (score 50-74)
sentyr scan files --min-risk 50 --max-risk 74

# Low risk (score 25-49)
sentyr scan files --min-risk 25 --max-risk 49
```

### Filter by User

```bash
# Specific user
sentyr scan files --user user@example.com

# Multiple users
sentyr scan files --user user1@example.com --user user2@example.com
```

### Filter by Date Range

```bash
# Files modified after date
sentyr scan files --after 2024-01-01

# Files modified before date
sentyr scan files --before 2024-12-31

# Date range
sentyr scan files --after 2024-01-01 --before 2024-12-31
```

### Filter by File Type

```bash
# Specific MIME type
sentyr scan files --mime-type "application/pdf"

# Multiple MIME types
sentyr scan files \
  --mime-type "application/pdf" \
  --mime-type "application/vnd.google-apps.document"

# Google Docs only
sentyr scan files --mime-type "application/vnd.google-apps.document"

# Google Sheets only
sentyr scan files --mime-type "application/vnd.google-apps.spreadsheet"
```

### Complex Filters

```bash
# High-risk PDFs shared externally
sentyr scan files \
  --external-only \
  --min-risk 75 \
  --mime-type "application/pdf"

# Files with PII modified in last 30 days
sentyr scan files \
  --check-pii \
  --after $(date -d '30 days ago' +%Y-%m-%d)

# Public files owned by specific users
sentyr scan files \
  --public-only \
  --user user1@example.com \
  --user user2@example.com
```

---

## Batch Operations

### Large-Scale Scanning

```bash
# Batch scan with progress tracking
sentyr scan files --batch-size 100 --show-progress

# Resume from checkpoint
sentyr scan files --resume-from checkpoint.json

# Save checkpoint every N items
sentyr scan files --checkpoint-interval 100 --checkpoint-dir ./checkpoints
```

### Batch Offboarding

```bash
# Offboard multiple users with checkpointing
sentyr offboard \
  --from-file users.txt \
  --batch-size 10 \
  --checkpoint-dir ./checkpoints \
  --execute

# Resume failed offboarding
sentyr offboard \
  --resume-from ./checkpoints/offboard_checkpoint.json \
  --execute
```

---

## Configuration Management

### Initialize Configuration

```bash
# Create default config
sentyr init

# Create config with specific path
sentyr init --output custom-config.yaml
```

### Test Configuration

```bash
# Test authentication
sentyr config test

# Test email alerts
sentyr config test-email

# Test Slack integration
sentyr config test-slack

# Test SIEM webhook
sentyr config test-webhook
```

### Validate Configuration

```bash
# Validate config file
sentyr config validate

# Validate specific config
sentyr config validate --config custom-config.yaml
```

---

## Tips & Best Practices

### 1. Always Use Dry-Run First

```bash
# Dry-run (safe)
sentyr offboard user@example.com

# Then execute
sentyr offboard user@example.com --execute
```

### 2. Use Incremental Scanning

```bash
# First scan (full)
sentyr scan files

# Subsequent scans (incremental - only changed files)
sentyr scan files --incremental
```

### 3. Monitor API Quotas

```bash
# Check quota usage
sentyr monitor metrics | grep quota

# Adjust rate limits in config.yaml
advanced:
  respect_api_quotas: true
  quota_buffer_percent: 20
```

### 4. Use Checkpoints for Large Operations

```bash
# Enable checkpointing
sentyr scan files \
  --checkpoint-dir ./checkpoints \
  --checkpoint-interval 100
```

### 5. Filter Results to Reduce Noise

```bash
# Focus on high-risk items
sentyr scan files --min-risk 75 --external-only
```

---

## Troubleshooting

### Authentication Issues

```bash
# Test authentication
sentyr config test

# Check credentials
sentyr config validate
```

### API Rate Limits

```bash
# Check rate limit status
sentyr monitor metrics --format table | grep rate

# Adjust rate limits in config.yaml
```

### Performance Issues

```bash
# Check system resources
sentyr monitor system

# Use batch processing
sentyr scan files --batch-size 50

# Enable incremental scanning
sentyr scan files --incremental
```

---

For more information, see:
- [Configuration Guide](configuration.md)
- [Authentication Guide](authentication.md)
- [Complete Feature List](FEATURES_COMPLETE.md)
- [Roadmap](roadmap.md)

