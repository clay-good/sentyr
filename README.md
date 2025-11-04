# Sentyr

**An AI agent framework for cybersecurity use cases, starting with security triage, analysis, and incident response.**

## Overview

Sentyr is a modular, extensible AI agent framework designed to tackle complex cybersecurity challenges through intelligent automation. Built on a foundation of specialized AI agents, Sentyr provides a flexible architecture for building sophisticated security workflows that combine machine learning, threat intelligence, and human expertise.

The framework currently focuses on two core capabilities:
- **Security Analysis & Triage**: Multi-phase threat detection, IOC enrichment, behavioral analysis, and MITRE ATT&CK mapping
- **Incident Response**: Complete incident lifecycle management from detection through post-mortem analysis

## Core Philosophy

Sentyr is built as a **framework, not a platform**. It provides:
- **Modular AI Agents**: Specialized agents that can be composed into workflows
- **Extensible Architecture**: Easy to add new agents and capabilities
- **Integration-Ready**: Designed to work with your existing security stack
- **Production-Grade**: Built with reliability, observability, and scalability in mind

## Architecture

Sentyr uses a layered architecture designed for modularity and extensibility:

```
┌─────────────────────────────────────────────────────────────┐
│                      API Layer                               │
│  REST API (FastAPI) | Python SDK | CLI                       │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent Layer                            │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │  Security        │      │  Incident        │            │
│  │  Analysis Agent  │      │  Response Agent  │            │
│  └──────────────────┘      └──────────────────┘            │
│                                                              │
│  ┌──────────────────────────────────────────┐              │
│  │  Agent Orchestrator                       │              │
│  │  (Multi-agent workflow coordination)      │              │
│  └──────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Processing Layer                          │
│  ML Engine | Behavioral Analysis | Threat Intel | Parsers   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                          │
│  Jira | PagerDuty | ServiceNow | Datadog | GitHub | GitLab  │
│  VirusTotal | AlienVault OTX | AbuseIPDB | Shodan           │
└─────────────────────────────────────────────────────────────┘
```

### Agent Framework

The framework provides a robust foundation for building AI-powered security agents:

- **BaseAgent**: Foundation class with async/await, caching, error handling, and observability
- **AgentContext**: Shared context for passing data between agents (incidents, IOCs, findings, timeline)
- **AgentOrchestrator**: Coordinates multi-agent workflows and manages task distribution
- **AgentCapability**: Enum defining agent capabilities for discovery and routing

## Core Agents

### Security Analysis Agent

The Security Analysis Agent performs comprehensive threat analysis using a multi-phase approach:

**Capabilities:**
- **12-Phase Analysis Pipeline**: IOC enrichment → Behavioral analysis → ML-powered detection → Threat actor attribution → AI reasoning
- **MITRE ATT&CK Mapping**: Automatic technique identification and attack chain reconstruction
- **Multi-Platform Parsers**: AWS GuardDuty, GCP Security Command Center, Datadog, CrowdStrike, Snowflake
- **IOC Enrichment**: Integration with VirusTotal, AlienVault OTX, AbuseIPDB, Shodan
- **Behavioral Analysis**: 8 attack pattern signatures with anomaly scoring
- **ML-Powered Detection**: Isolation Forest for anomaly detection, Random Forest for threat prediction
- **Threat Actor Attribution**: Correlation with known APT groups and TTPs

**Output:**
- Executive summary with risk scoring (0-10)
- 5W1H analysis (Who, What, When, Where, Why, How)
- MITRE ATT&CK techniques with confidence scores
- Attack chain timeline
- Immediate actions and recommendations
- Investigation queries for further analysis

### Incident Response Agent

The Incident Response Agent manages the complete incident lifecycle:

**Capabilities:**
- **Lifecycle Management**: Detection → Analysis → Containment → Eradication → Recovery → Post-Incident
- **Timeline Reconstruction**: Correlate events across system logs, EDR, network, and human actions
- **Root Cause Analysis**: Identify initial attack vectors and contributing factors
- **Impact Assessment**: Calculate MTTD, MTTC, MTTR and assess business impact
- **Post-Mortem Generation**: BLUF-style reports with 5W1H framework
- **Corrective Action Planning**: Technical remediation, process improvements, and training recommendations
- **Ticketing Integration**: Automatic issue creation in Jira, ServiceNow, PagerDuty

**Output:**
- Comprehensive incident timeline
- Root cause analysis with confidence scoring
- Business impact metrics (financial, reputational, regulatory)
- Post-mortem report with lessons learned
- Prioritized corrective action plan
- Compliance reporting artifacts

## Project Structure

```
sentyr/
├── sentyr/                     # Core framework code
│   ├── agents/                 # AI agent implementations
│   │   ├── framework.py        # Base agent framework and orchestrator
│   │   ├── base.py             # Legacy base agent class
│   │   ├── security_analyst.py # Security analysis agent (legacy)
│   │   ├── security_analysis.py # Security analysis agent (framework)
│   │   ├── incident_response.py # Incident response agent
│   │   └── orchestrator.py     # Multi-agent orchestration
│   ├── parsers/                # Security event parsers
│   │   ├── base.py             # Base parser interface
│   │   ├── guardduty.py        # AWS GuardDuty
│   │   ├── gcp_scc.py          # GCP Security Command Center
│   │   ├── datadog.py          # Datadog Security
│   │   ├── crowdstrike.py      # CrowdStrike EDR
│   │   └── snowflake.py        # Snowflake Security
│   ├── integrations/           # External service integrations
│   │   ├── jira_integration.py # Jira ticketing
│   │   ├── servicenow_integration.py # ServiceNow ITSM
│   │   ├── pagerduty_integration.py # PagerDuty alerting
│   │   ├── datadog_integration.py # Datadog monitoring
│   │   ├── github_integration.py # GitHub automation
│   │   └── gitlab_integration.py # GitLab automation
│   ├── api.py                  # FastAPI REST API
│   ├── cli.py                  # Command-line interface
│   ├── models.py               # Data models (Pydantic)
│   ├── config.py               # Configuration management
│   ├── logger.py               # Structured logging
│   ├── ml_engine.py            # Machine learning engine
│   ├── behavioral_analysis.py  # Behavioral analysis engine
│   ├── threat_intel.py         # Threat intelligence engine
│   ├── threat_feeds.py         # External threat feed integration
│   ├── correlation.py          # Event correlation
│   ├── streaming.py            # Real-time event streaming
│   ├── forensics.py            # Digital forensics
│   ├── playbooks.py            # Automated response playbooks
│   ├── incidents.py            # Incident management
│   ├── notifications.py        # Alert notifications
│   ├── webhooks.py             # Webhook handlers
│   ├── cache.py                # Caching layer
│   ├── metrics.py              # Metrics collection
│   ├── infrastructure/         # Infrastructure components
│   │   ├── message_queue.py    # RabbitMQ integration
│   │   └── redis_cache.py      # Redis caching
│   ├── monitoring/             # Observability
│   │   ├── metrics.py          # Prometheus metrics
│   │   └── tracing.py          # OpenTelemetry tracing
│   └── security/               # Security utilities
│       ├── secrets_manager.py  # Secrets management
│       └── password_manager.py # Password hashing
├── tests/                      # Test suites
├── docs/                       # Documentation
│   ├── agents/                 # Agent documentation
│   └── integrations/           # Integration guides
├── examples/                   # Example usage
│   └── api_client.py           # Python SDK example
├── config/                     # Configuration files
│   ├── development.yaml        # Development config
│   ├── staging.yaml            # Staging config
│   └── production.yaml         # Production config
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Poetry configuration
└── README.md                   # This file
```

## Framework Capabilities

### Event Parsing & Normalization
- **Multi-Platform Support**: AWS GuardDuty, GCP SCC, Datadog, CrowdStrike, Snowflake
- **Unified Event Model**: Normalize events from different sources into a common schema
- **IOC Extraction**: Automatic extraction of IPs, domains, URLs, file hashes, user accounts

### Machine Learning
- **Anomaly Detection**: Isolation Forest for detecting unusual patterns (7 anomaly types)
- **Threat Prediction**: Random Forest classifier for predicting attack types (8 categories)
- **Feature Engineering**: Automatic feature extraction from security events
- **Model Training**: Support for online learning and model updates

### Behavioral Analysis
- **Attack Pattern Recognition**: 8 built-in attack signatures (cryptojacking, ransomware, data exfiltration, etc.)
- **Anomaly Scoring**: Confidence-based scoring for behavioral anomalies
- **Temporal Analysis**: Time-series analysis for detecting suspicious patterns

### Threat Intelligence
- **Multi-Source Enrichment**: VirusTotal, AlienVault OTX, AbuseIPDB, Shodan
- **Smart Caching**: Redis-backed caching for 4-5x performance improvement
- **Reputation Scoring**: Aggregate reputation scores from multiple sources
- **Batch Processing**: Efficient bulk IOC enrichment

### Incident Management
- **Lifecycle Tracking**: Manage incidents through all phases (detection → recovery)
- **Timeline Reconstruction**: Correlate events across multiple data sources
- **Metrics Calculation**: MTTD, MTTC, MTTR, and business impact assessment
- **Audit Trail**: Complete audit logging with cryptographic verification

### Automated Response
- **Playbook Execution**: Pre-built playbooks for common scenarios (ransomware, data exfiltration, etc.)
- **Response Actions**: Isolate host, block IP, disable user, quarantine file, etc.
- **Approval Workflows**: Multi-level approval for sensitive actions
- **Rollback Support**: Ability to undo automated actions

### Integrations
- **Ticketing**: Jira, ServiceNow, PagerDuty
- **Monitoring**: Datadog
- **Development**: GitHub, GitLab
- **Threat Intel**: VirusTotal, AlienVault OTX, AbuseIPDB, Shodan



## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sentyr.git
cd sentyr

# Install dependencies
pip install -r requirements.txt

# Or use Poetry
poetry install

# Set up configuration
export SENTYR_ENV=development
export ANTHROPIC_API_KEY=your-claude-api-key
```

### Basic Usage

```python
from sentyr.agents.security_analyst import SecurityAnalystAgent
from sentyr.agents.incident_response import IncidentResponseAgent
from sentyr.parsers.guardduty import GuardDutyParser
from sentyr.config import get_config

# Initialize configuration
config = get_config()

# Parse a security event
parser = GuardDutyParser()
event = parser.parse(guardduty_finding)

# Analyze with Security Analysis Agent
analyst = SecurityAnalystAgent(config)
analysis = await analyst.analyze([event])

print(f"Risk Score: {analysis.risk_score}/10")
print(f"Executive Summary: {analysis.executive_summary}")
print(f"MITRE Techniques: {[t.technique_id for t in analysis.mitre_techniques]}")

# Create incident and perform incident response
ir_agent = IncidentResponseAgent(config)
incident_output = await ir_agent.execute(agent_input)

print(f"Root Cause: {incident_output.results['root_cause']}")
print(f"Corrective Actions: {incident_output.results['corrective_actions']}")
```

### Running the API Server

```bash
# Start the FastAPI server
python -m sentyr.api

# API will be available at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### Using the CLI

```bash
# Analyze a security event
sentyr analyze --file event.json --parser guardduty

# Run incident response
sentyr incident respond --incident-id INC-001

# Check agent status
sentyr agent status
```

## Configuration

Configuration is managed through YAML files in the `config/` directory and environment variables.

### Configuration Files

- `config/development.yaml` - Development environment settings
- `config/staging.yaml` - Staging environment settings
- `config/production.yaml` - Production environment settings

### Environment Variables

```bash
# Core Configuration
export SENTYR_ENV=development  # or staging, production
export ANTHROPIC_API_KEY=your-claude-api-key

# Optional: Database (defaults to SQLite)
export SENTYR_DB_URL=postgresql://user:pass@host:5432/sentyr

# Optional: Redis Cache
export REDIS_URL=redis://localhost:6379/0

# Optional: Threat Intelligence APIs
export VIRUSTOTAL_API_KEY=your-key
export ALIENVAULT_OTX_API_KEY=your-key
export ABUSEIPDB_API_KEY=your-key
export SHODAN_API_KEY=your-key

# Optional: Ticketing Integrations
export JIRA_URL=https://your-company.atlassian.net
export JIRA_USERNAME=user@example.com
export JIRA_API_TOKEN=your-token
export JIRA_PROJECT_KEY=SEC

export PAGERDUTY_API_KEY=your-key
export SERVICENOW_URL=https://your-instance.service-now.com
export SERVICENOW_USERNAME=your-username
export SERVICENOW_PASSWORD=your-password

# Optional: Monitoring
export DATADOG_API_KEY=your-key
```

## Extending the Framework

### Creating a Custom Agent

```python
from sentyr.agents.framework import BaseAgent, AgentCapability, AgentInput, AgentOutput
from sentyr.config import SentyrConfig

class MyCustomAgent(BaseAgent):
    """Custom agent for specialized security tasks"""

    def __init__(self, config: SentyrConfig):
        super().__init__(
            agent_id="my-custom-agent",
            agent_name="My Custom Agent",
            agent_version="1.0.0",
            capabilities=[AgentCapability.CUSTOM],
            description="Custom security agent"
        )
        self.config = config

    async def execute(self, input_data: AgentInput) -> AgentOutput:
        """Execute custom agent logic"""
        # Your custom logic here
        results = {"status": "completed"}

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results=results,
            confidence=0.9,
            reasoning=["Custom analysis performed"],
            data_sources_used=["custom_source"],
            recommendations=[],
            next_actions=[],
            audit_trail=[],
            execution_time=1.0
        )
```

### Creating a Custom Parser

```python
from sentyr.parsers.base import BaseParser
from sentyr.models import SecurityEvent, TechnicalIndicator

class MyCustomParser(BaseParser):
    """Parser for custom security event format"""

    def parse(self, raw_event: dict) -> SecurityEvent:
        """Parse custom event format into SecurityEvent"""
        return SecurityEvent(
            event_id=raw_event["id"],
            source="my-custom-source",
            event_type=raw_event["type"],
            severity=raw_event["severity"],
            timestamp=raw_event["timestamp"],
            description=raw_event["description"],
            technical_indicators=[
                TechnicalIndicator(
                    indicator_type="ip",
                    value=raw_event["source_ip"]
                )
            ],
            raw_event=raw_event
        )
```

## System Requirements

### Minimum Requirements
- Python 3.11+
- 2 CPU cores
- 4GB RAM
- 20GB disk space

### Recommended for Production
- Python 3.11+
- 8+ CPU cores
- 16GB+ RAM
- 100GB SSD storage
- PostgreSQL 15+ (optional, defaults to SQLite)
- Redis 7+ (optional, for caching)
- RabbitMQ 3.8+ (optional, for message queuing)

## Performance Characteristics

- **Event Processing**: <100ms latency per event
- **ML Inference**: <150ms for threat prediction
- **Anomaly Detection**: <100ms per event
- **API Response Time**: <200ms (p95)
- **Agent Execution**: 1-5s average (depending on enrichment)

## Security Features

- **Secrets Management**: Support for Vault, AWS Secrets Manager, Azure Key Vault
- **Password Hashing**: Bcrypt/Argon2 for credential storage
- **API Security**: Rate limiting, authentication, CORS
- **Audit Logging**: Complete audit trail for all agent actions
- **Input Validation**: Pydantic-based validation for all inputs

## Observability

- **Metrics**: Prometheus metrics export
- **Tracing**: OpenTelemetry distributed tracing
- **Logging**: Structured logging with correlation IDs (structlog)
- **Health Checks**: `/health` endpoint for monitoring
- **Performance Profiling**: Built-in profiling support

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test suite
pytest tests/test_enhanced_security_analyst.py

# Run with coverage
pytest --cov=sentyr tests/

# Run with verbose output
pytest -v tests/
```

## Roadmap

The framework is designed to be extended with additional agents and capabilities:

**Planned Agents:**
- Vulnerability Management Agent
- Detection Engineering Agent
- Threat Hunting Agent
- Compliance Reporting Agent
- Brand Protection Agent

**Planned Features:**
- Multi-agent orchestration workflows
- Agent marketplace for community contributions
- Enhanced ML models (LSTM, Transformers)
- Real-time streaming analytics
- Advanced forensics capabilities

## Contributing

We welcome contributions! Areas where you can help:
- New agent implementations
- Additional security event parsers
- Integration with more security tools
- Documentation improvements
- Bug fixes and performance optimizations

## License

See [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

## Acknowledgments

Built with:
- [Anthropic Claude](https://www.anthropic.com/) - AI reasoning engine
- [FastAPI](https://fastapi.tiangolo.com/) - API framework
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation
- [scikit-learn](https://scikit-learn.org/) - Machine learning
- [structlog](https://www.structlog.org/) - Structured logging

