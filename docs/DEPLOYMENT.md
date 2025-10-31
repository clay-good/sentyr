# Sentyr Deployment Guide

This guide covers deploying Sentyr in various environments including Docker, Kubernetes, and systemd.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Systemd Service](#systemd-service)
5. [Configuration Management](#configuration-management)
6. [Monitoring & Logging](#monitoring--logging)
7. [Security Best Practices](#security-best-practices)

---

## Prerequisites

### Required
- Python 3.10 or higher
- Google Workspace Admin account
- Service account with appropriate permissions
- Poetry (for dependency management)

### Google Workspace API Permissions
Your service account needs the following scopes:
- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
- `https://www.googleapis.com/auth/drive.readonly`
- `https://www.googleapis.com/auth/gmail.readonly`
- `https://www.googleapis.com/auth/admin.directory.domain.readonly`

### Domain-Wide Delegation
Enable domain-wide delegation for your service account in Google Workspace Admin Console.

---

## Docker Deployment

### 1. Create Dockerfile

Create a `Dockerfile` in your project root:

```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY sentyr ./sentyr
COPY README.md ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Create directories for config and data
RUN mkdir -p /app/config /app/data /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SENTYR_CONFIG=/app/config/config.yaml

# Run as non-root user
RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app
USER sentinel

# Default command
ENTRYPOINT ["sentyr"]
CMD ["--help"]
```

### 2. Create docker-compose.yml

```yaml
version: '3.8'

services:
  sentyr:
    build: .
    container_name: sentyr
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - SENTYR_CONFIG=/app/config/config.yaml
      - TZ=UTC
    restart: unless-stopped
    command: scan files --external-only --check-pii
```

### 3. Build and Run

```bash
# Build the image
docker build -t sentyr:latest .

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f

# Run one-off commands
docker-compose run --rm sentyr scan users --inactive-days 90
```

### 4. Docker Environment Variables

```bash
# Configuration
SENTYR_CONFIG=/app/config/config.yaml

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Performance
BATCH_SIZE=100
RATE_LIMIT_DELAY=0.1
ENABLE_CACHE=true
```

---

## Kubernetes Deployment

### 1. Create ConfigMap

`k8s/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sentyr-config
  namespace: security
data:
  config.yaml: |
    google_workspace:
      domain: "example.com"
      admin_email: "admin@example.com"
      service_account_file: "/secrets/service-account.json"
    
    scanning:
      batch_size: 100
      rate_limit_delay: 0.1
      enable_cache: true
    
    logging:
      level: "INFO"
      format: "json"
```

### 2. Create Secret

```bash
# Create secret from service account JSON
kubectl create secret generic sentyr-secrets \
  --from-file=service-account.json=./service-account.json \
  --namespace=security
```

### 3. Create Deployment

`k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentyr
  namespace: security
  labels:
    app: sentyr
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sentyr
  template:
    metadata:
      labels:
        app: sentyr
    spec:
      serviceAccountName: sentyr
      containers:
      - name: sentyr
        image: sentyr:latest
        imagePullPolicy: IfNotPresent
        command: ["sentyr"]
        args: ["scan", "files", "--external-only", "--check-pii"]
        env:
        - name: SENTYR_CONFIG
          value: "/config/config.yaml"
        - name: LOG_LEVEL
          value: "INFO"
        volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true
        - name: secrets
          mountPath: /secrets
          readOnly: true
        - name: data
          mountPath: /app/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: sentyr-config
      - name: secrets
        secret:
          secretName: sentyr-secrets
      - name: data
        persistentVolumeClaim:
          claimName: sentyr-data
```

### 4. Create CronJob for Scheduled Scans

`k8s/cronjob.yaml`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: sentyr-daily-scan
  namespace: security
spec:
  schedule: "0 2 * * *"  # Run at 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: sentyr
          containers:
          - name: sentyr
            image: sentyr:latest
            command: ["sentyr"]
            args: 
            - "scan"
            - "files"
            - "--external-only"
            - "--check-pii"
            - "--incremental"
            - "--output"
            - "/app/data/scan-results.json"
            - "--format"
            - "json"
            env:
            - name: SENTYR_CONFIG
              value: "/config/config.yaml"
            volumeMounts:
            - name: config
              mountPath: /config
              readOnly: true
            - name: secrets
              mountPath: /secrets
              readOnly: true
            - name: data
              mountPath: /app/data
          restartPolicy: OnFailure
          volumes:
          - name: config
            configMap:
              name: sentyr-config
          - name: secrets
            secret:
              secretName: sentyr-secrets
          - name: data
            persistentVolumeClaim:
              claimName: sentyr-data
```

### 5. Create PersistentVolumeClaim

`k8s/pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: sentyr-data
  namespace: security
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
```

### 6. Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace security

# Apply configurations
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/cronjob.yaml

# Check status
kubectl get pods -n security
kubectl logs -f deployment/sentyr -n security

# Run manual scan
kubectl run sentyr-manual \
  --image=sentyr:latest \
  --restart=Never \
  --namespace=security \
  -- scan files --external-only
```

---

## Systemd Service

### 1. Create Service File

`/etc/systemd/system/sentyr.service`:

```ini
[Unit]
Description=Sentyr Security Scanner
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel
Group=sentinel
WorkingDirectory=/opt/sentyr
Environment="PATH=/opt/sentyr/.venv/bin:/usr/local/bin:/usr/bin"
Environment="SENTYR_CONFIG=/etc/sentyr/config.yaml"
ExecStart=/opt/sentyr/.venv/bin/sentyr scan files --external-only --check-pii --incremental
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentyr

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sentyr /var/log/sentyr

[Install]
WantedBy=multi-user.target
```

### 2. Create Timer for Scheduled Scans

`/etc/systemd/system/sentyr.timer`:

```ini
[Unit]
Description=Sentyr Daily Scan Timer
Requires=sentyr.service

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

### 3. Installation Steps

```bash
# Create user
sudo useradd -r -s /bin/false sentinel

# Create directories
sudo mkdir -p /opt/sentyr
sudo mkdir -p /etc/sentyr
sudo mkdir -p /var/lib/sentyr
sudo mkdir -p /var/log/sentyr

# Set permissions
sudo chown -R sentinel:sentinel /opt/sentyr
sudo chown -R sentinel:sentinel /var/lib/sentyr
sudo chown -R sentinel:sentinel /var/log/sentyr

# Install application
cd /opt/sentyr
sudo -u sentinel poetry install

# Copy configuration
sudo cp config.yaml /etc/sentyr/
sudo chown sentinel:sentinel /etc/sentyr/config.yaml
sudo chmod 600 /etc/sentyr/config.yaml

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable sentyr.timer
sudo systemctl start sentyr.timer

# Check status
sudo systemctl status sentyr.timer
sudo journalctl -u sentyr -f
```

---

## Configuration Management

### Environment-Specific Configs

Create separate configs for each environment:

```
config/
├── production.yaml
├── staging.yaml
└── development.yaml
```

### Using Environment Variables

Override config values with environment variables:

```bash
export GWS_DOMAIN="example.com"
export GWS_ADMIN_EMAIL="admin@example.com"
export GWS_SERVICE_ACCOUNT_FILE="/path/to/service-account.json"
```

---

## Monitoring & Logging

### Structured Logging

Sentyr uses structured logging (JSON format) for easy parsing:

```json
{
  "timestamp": "2025-10-28T10:30:00Z",
  "level": "INFO",
  "event": "scan_completed",
  "files_scanned": 1234,
  "issues_found": 5
}
```

### Integration with Log Aggregators

**Elasticsearch/Kibana:**
```bash
# Forward logs to Elasticsearch
docker run -d \
  --log-driver=fluentd \
  --log-opt fluentd-address=localhost:24224 \
  sentyr:latest
```

**Splunk:**
```bash
# Use Splunk Universal Forwarder
/opt/splunkforwarder/bin/splunk add monitor /var/log/sentyr
```

---

## Security Best Practices

### 1. Credential Management
- ✅ Never commit service account JSON to version control
- ✅ Use Kubernetes secrets or HashiCorp Vault
- ✅ Rotate service account keys regularly (every 90 days)
- ✅ Use least-privilege permissions

### 2. Network Security
- ✅ Run in private network/VPC
- ✅ Use firewall rules to restrict outbound traffic
- ✅ Enable TLS for all external communications

### 3. Container Security
- ✅ Run as non-root user
- ✅ Use minimal base images
- ✅ Scan images for vulnerabilities
- ✅ Keep dependencies updated

### 4. Access Control
- ✅ Limit who can deploy/modify
- ✅ Use RBAC in Kubernetes
- ✅ Audit all configuration changes

---

## Next Steps

- [Getting Started Guide](GETTING_STARTED.md)
- [Configuration Examples](examples/)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

