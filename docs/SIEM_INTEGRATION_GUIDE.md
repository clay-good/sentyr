# Sentyr SIEM Integration Guide

## Overview

Sentyr enriches SIEM alerts and incidents with AI-powered analysis, threat intelligence, and actionable recommendations. This guide shows security teams how to integrate Sentyr with common SIEMs.

---

## Table of Contents
1. [Quick Start](#quick-start)
2. [Supported SIEMs](#supported-siems)
3. [Integration Methods](#integration-methods)
4. [Example Integrations](#example-integrations)
5. [Enrichment Workflow](#enrichment-workflow)
6. [Best Practices](#best-practices)

---

## Quick Start

### Prerequisites
- Sentyr API running (see main README)
- SIEM with outbound webhook/API capabilities
- API authentication configured

### 5-Minute Setup
```bash
# 1. Start Sentyr
python -m sentyr.cli serve

# 2. Test enrichment endpoint
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source": "splunk",
    "event": {
      "alert_name": "Suspicious PowerShell Execution",
      "severity": "high",
      "source_ip": "10.1.2.3",
      "user": "john.doe",
      "timestamp": "2025-01-10T15:30:00Z"
    }
  }'

# 3. Configure SIEM webhook to POST to /analyze
```

---

## Supported SIEMs

### Fully Supported (Native Parsers)
- **Splunk** - Via REST API or webhook
- **Datadog Security Monitoring** - Native parser included
- **AWS GuardDuty** - Direct integration
- **GCP Security Command Center** - Built-in support
- **CrowdStrike Falcon** - EDR event parser
- **Snowflake Security** - Query result enrichment

### Generic Support
- **Elastic Security** - JSON webhook
- **Microsoft Sentinel** - Logic Apps integration
- **IBM QRadar** - Custom action
- **Sumo Logic** - Webhook connection
- **Chronicle** - API integration

---

## Integration Methods

### Method 1: Webhook (Recommended)
**Best for**: Real-time alert enrichment

```python
# SIEM sends webhook to Sentyr on alert trigger
POST /analyze HTTP/1.1
Host: sentyr.company.com
Content-Type: application/json

{
  "source": "splunk",
  "event": {
    "alert_name": "Brute Force Authentication Attempt",
    "severity": "high",
    "source_ip": "198.51.100.42",
    "destination": "login.company.com",
    "failed_attempts": 25,
    "user": "admin",
    "timestamp": "2025-01-10T15:30:00Z",
    "raw_log": "Jan 10 15:30:00 sshd[1234]: Failed password for admin from 198.51.100.42"
  }
}
```

**Response** (2-5 seconds):
```json
{
  "event_id": "evt_abc123",
  "risk_score": 8.5,
  "confidence": 0.92,
  "executive_summary": "Critical: Automated brute force attack from known malicious IP targeting privileged account. Attack is ongoing and requires immediate containment.",
  "five_w1h": {
    "who": "Automated attacker from botnet IP 198.51.100.42 (confidence: 0.95)",
    "what": "SSH brute force attack targeting admin account",
    "when": "Started 15:30 UTC, 25 attempts in 2 minutes",
    "where": "login.company.com (public-facing SSH server)",
    "why": "Credential harvesting for initial access",
    "how": "Automated password spraying using common passwords"
  },
  "mitre_techniques": [
    {
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "tactic": "Credential Access",
      "confidence": 0.95,
      "evidence": "25 failed login attempts in 2 minutes from single IP"
    }
  ],
  "immediate_actions": [
    "CRITICAL (0-15min): Block IP 198.51.100.42 at perimeter firewall",
    "HIGH (15-30min): Force password reset for admin account and enable MFA",
    "HIGH (30-60min): Review access logs for any successful authentications from this IP"
  ],
  "threat_intelligence": {
    "ip_reputation": "malicious",
    "threat_score": 95,
    "threat_feeds_detected": ["AbuseIPDB", "AlienVault OTX"],
    "associated_campaigns": ["SSH-Botnet-2025"],
    "first_seen": "2025-01-01",
    "attack_count": 127
  },
  "processing_time_seconds": 2.3
}
```

### Method 2: Scheduled Batch Enrichment
**Best for**: Historical analysis, bulk processing

```bash
# Export SIEM alerts to JSON
# Run batch enrichment
python -m sentyr.cli batch --input siem_alerts.json --output enriched_results.json

# Import enriched data back to SIEM
```

### Method 3: API Integration
**Best for**: Custom workflows, automation

```python
import requests

def enrich_siem_alert(alert):
    """Enrich SIEM alert with Sentyr analysis"""
    response = requests.post(
        "https://sentyr.company.com/analyze",
        json={
            "source": "custom_siem",
            "event": alert,
            "enable_rag": True,  # Include historical context
            "enable_cache": True  # Use caching for performance
        },
        headers={"Authorization": "Bearer YOUR_API_KEY"}
    )

    enrichment = response.json()

    # Add enrichment back to SIEM as note/comment
    update_siem_alert(
        alert_id=alert['id'],
        notes=f"""
        AI Analysis (Risk: {enrichment['risk_score']}/10):
        {enrichment['executive_summary']}

        Immediate Actions:
        {chr(10).join(enrichment['immediate_actions'])}
        """
    )

    return enrichment
```

---

## Example Integrations

### Splunk

#### Option A: Alert Action (Webhook)
```xml
<!-- savedsearches.conf -->
[Suspicious Activity Alert]
action.webhook = 1
action.webhook.param.url = https://sentyr.company.com/analyze
action.webhook.param.method = POST
action.webhook.param.headers = Content-Type:application/json|Authorization:Bearer YOUR_KEY
action.webhook.param.payload = {
  "source": "splunk",
  "event": {
    "alert_name": "$name$",
    "severity": "$severity$",
    "source_ip": "$source_ip$",
    "user": "$user$",
    "timestamp": "$_time$",
    "search_results": $results$
  }
}
```

#### Option B: Python Script
```python
# bin/sentyr_enrich.py
import sys
import requests
import json

# Get Splunk event
events = json.loads(sys.stdin.read())

for event in events:
    # Enrich with Sentyr
    response = requests.post(
        "https://sentyr.company.com/analyze",
        json={"source": "splunk", "event": event}
    )
    enrichment = response.json()

    # Write enrichment back to Splunk
    print(json.dumps({
        "original_event": event,
        "sentyr_enrichment": enrichment
    }))
```

### Datadog

```python
# Datadog Webhook Integration
# Navigate to: Integrations > Webhooks

# Webhook URL: https://sentyr.company.com/analyze
# Headers:
#   Content-Type: application/json
#   Authorization: Bearer YOUR_API_KEY

# Payload:
{
  "source": "datadog",
  "event": {
    "alert_name": "$EVENT_TITLE",
    "severity": "$ALERT_PRIORITY",
    "source_ip": "$IP",
    "timestamp": "$DATE",
    "message": "$TEXT_ONLY_MSG",
    "tags": "$TAGS"
  }
}
```

### Microsoft Sentinel (Azure Logic Apps)

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "Enrich_with_Sentyr": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://sentyr.company.com/analyze",
          "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer @{parameters('SentyrAPIKey')}"
          },
          "body": {
            "source": "sentinel",
            "event": "@triggerBody()?['object']"
          }
        }
      },
      "Update_Incident": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          },
          "method": "put",
          "path": "/Incidents",
          "body": {
            "properties": {
              "description": "@{body('Enrich_with_Sentyr')?['executive_summary']}",
              "severity": "@{body('Enrich_with_Sentyr')?['risk_score']}"
            }
          }
        }
      }
    }
  }
}
```

### AWS GuardDuty (EventBridge + Lambda)

```python
# lambda_function.py
import json
import boto3
import requests

def lambda_handler(event, context):
    """Enrich GuardDuty finding with Sentyr"""

    # Extract GuardDuty finding
    finding = event['detail']

    # Enrich with Sentyr
    response = requests.post(
        "https://sentyr.company.com/analyze",
        json={
            "source": "guardduty",
            "event": finding
        },
        headers={"Authorization": f"Bearer {os.environ['SENTYR_API_KEY']}"}
    )

    enrichment = response.json()

    # Update finding in Security Hub
    securityhub = boto3.client('securityhub')
    securityhub.batch_update_findings(
        FindingIdentifiers=[{
            'Id': finding['id'],
            'ProductArn': finding['productArn']
        }],
        Note={
            'Text': enrichment['executive_summary'],
            'UpdatedBy': 'Sentyr-AI'
        }
    )

    # Create Jira ticket for high-risk findings
    if enrichment['risk_score'] >= 7.0:
        create_jira_ticket(enrichment)

    return {
        'statusCode': 200,
        'body': json.dumps(enrichment)
    }
```

---

## Enrichment Workflow

### Standard Workflow
```
1. SIEM detects security event
   ↓
2. SIEM triggers webhook/API call to Sentyr
   ↓
3. Sentyr performs multi-phase analysis:
   - IOC enrichment (threat intel lookup)
   - Behavioral analysis (pattern detection)
   - ML anomaly detection
   - MITRE ATT&CK mapping
   - Historical correlation
   - AI reasoning (Claude analysis)
   ↓
4. Sentyr returns enriched analysis (2-5s)
   ↓
5. SIEM updates alert with:
   - Risk score
   - Executive summary
   - Immediate actions
   - MITRE techniques
   - Investigation queries
   ↓
6. Optional: Auto-create ticket in Jira/ServiceNow
```

### Advanced Workflow (with Auto-Response)
```
1-5. Same as standard workflow
   ↓
6. If risk_score >= 8.0:
   - Create P1 incident ticket
   - Page on-call engineer
   - Execute automated containment:
     * Block malicious IPs at firewall
     * Disable compromised accounts
     * Isolate affected hosts
   ↓
7. Update SIEM with action results
```

---

## Best Practices

### 1. Alert Filtering
**Don't enrich everything** - focus on high-value alerts:
```python
# Only enrich high/critical severity alerts
if alert['severity'] in ['high', 'critical']:
    enrichment = enrich_with_sentyr(alert)
```

### 2. Caching Strategy
Enable caching for similar alerts:
```json
{
  "enable_cache": true,  // Reuse analysis for similar events
  "cache_ttl_hours": 24  // Cache validity period
}
```

### 3. Rate Limiting
Respect API limits:
```python
from ratelimit import limits, sleep_and_retry

@sleep_and_retry
@limits(calls=100, period=60)  # 100 req/min
def enrich_alert(alert):
    return sentyr_client.analyze(alert)
```

### 4. Error Handling
Always handle API failures gracefully:
```python
try:
    enrichment = enrich_with_sentyr(alert)
except requests.exceptions.Timeout:
    logger.warning(f"Sentyr timeout for alert {alert['id']}")
    enrichment = {"status": "timeout"}
except requests.exceptions.RequestException as e:
    logger.error(f"Sentyr error: {e}")
    enrichment = {"status": "error"}
```

### 5. Field Mapping
Map SIEM fields to Sentyr format:
```python
FIELD_MAPPING = {
    'splunk': {
        'src': 'source_ip',
        'dest': 'destination_ip',
        'user': 'username'
    },
    'sentinel': {
        'SourceIP': 'source_ip',
        'AccountName': 'username'
    }
}

def map_fields(siem_type, event):
    mapping = FIELD_MAPPING.get(siem_type, {})
    return {mapping.get(k, k): v for k, v in event.items()}
```

### 6. Metrics & Monitoring
Track enrichment performance:
```python
# Log metrics
metrics = {
    'alerts_enriched': counter,
    'avg_latency_ms': avg_latency,
    'cache_hit_rate': cache_hits / total_requests,
    'high_risk_alerts': high_risk_count
}
```

---

## Troubleshooting

### Slow Enrichment
**Problem**: Enrichment takes >10 seconds
**Solution**:
- Enable Redis caching: `use_redis_cache=true`
- Reduce context events
- Use batch mode for historical analysis

### High False Positives
**Problem**: Too many alerts flagged as high-risk
**Solution**:
- Adjust risk scoring thresholds
- Enable RAG for historical context
- Fine-tune alert filtering

### Authentication Errors
**Problem**: 401 Unauthorized
**Solution**:
```bash
# Check API key
curl -H "Authorization: Bearer YOUR_KEY" https://sentyr.company.com/health

# Verify CORS origins
export SENTYR_ALLOWED_ORIGINS=https://your-siem.com
```

---

## Example Output for Security Teams

### Sample Enriched Alert

**Original SIEM Alert:**
```
Title: Multiple Failed Login Attempts
Severity: Medium
Source IP: 203.0.113.42
User: admin
Count: 15
```

**After Sentyr Enrichment:**
```
Title: [HIGH RISK] Automated Credential Stuffing Attack
Risk Score: 8.5/10 (Confidence: 92%)

EXECUTIVE SUMMARY:
Automated credential stuffing attack from known botnet IP targeting privileged
account. Attack pattern matches recent campaign affecting 50+ organizations.
Immediate containment required.

THREAT INTELLIGENCE:
- IP 203.0.113.42: Known malicious (95% confidence)
- Associated with "Credential-Harvester-2025" campaign
- Previously seen attacking 127 organizations
- First observed: 2025-01-01

MITRE ATT&CK:
- T1110.004: Brute Force: Credential Stuffing
- T1078: Valid Accounts
- T1133: External Remote Services

IMMEDIATE ACTIONS (Next 1 hour):
1. CRITICAL (0-15min): Block IP 203.0.113.42 at perimeter firewall
2. HIGH (15-30min): Force password reset for admin account + enable MFA
3. HIGH (30-60min): Audit all accounts for compromise indicators

INVESTIGATION QUERIES:
- Splunk: index=auth src_ip="203.0.113.42" | stats count by user, result
- EDR: process_name IN (ssh, rdp, vpn) AND network.remote_ip="203.0.113.42"

BUSINESS IMPACT:
- Potential admin account compromise: HIGH
- Data exfiltration risk: MEDIUM
- Estimated containment cost: $5,000
- Regulatory exposure: GDPR (if EU data accessed)
```

---

## Support

- **Documentation**: https://github.com/sentyr/sentyr/docs
- **API Reference**: http://localhost:8000/docs
- **Issues**: https://github.com/sentyr/sentyr/issues
- **Community**: Discord/Slack channel

---

## Next Steps

1. Review [API Documentation](../README.md)
2. Test enrichment with sample alerts
3. Configure webhook in your SIEM
4. Monitor enrichment metrics
5. Tune risk scoring thresholds
6. Enable auto-response for high-risk alerts
