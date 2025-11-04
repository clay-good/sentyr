"""
AI agents for security analysis and incident response.

Sentyr Agent Framework - Modular AI agents for cybersecurity operations.
"""

# Legacy base agent (for backward compatibility)
from .base import BaseAgent as LegacyBaseAgent

# Legacy security analyst (for backward compatibility)
from .security_analyst import SecurityAnalystAgent as LegacySecurityAnalystAgent
from .security_analyst import SecurityAnalystAgent  # Also export with original name

# New agent framework
from .framework import (
    BaseAgent,
    AgentCapability,
    AgentStatus,
    AgentPriority,
    AgentContext,
    AgentInput,
    AgentOutput,
    AgentMetadata,
    AgentRegistry,
    get_agent_registry
)

from .orchestrator import (
    AgentOrchestrator,
    WorkflowDefinition,
    WorkflowStep,
    WorkflowExecution,
    WorkflowStatus,
    ExecutionMode,
    get_orchestrator
)

# Core agents
from .security_analysis import SecurityAnalysisAgent
from .incident_response import (
    IncidentResponseAgent,
    IncidentPhase,
    IncidentSeverity,
    IncidentMetrics,
    ImpactAssessment
)

__all__ = [
    # Legacy (backward compatibility)
    "LegacyBaseAgent",
    "LegacySecurityAnalystAgent",
    "SecurityAnalystAgent",  # Also export with original name

    # Framework core
    "BaseAgent",
    "AgentCapability",
    "AgentStatus",
    "AgentPriority",
    "AgentContext",
    "AgentInput",
    "AgentOutput",
    "AgentMetadata",
    "AgentRegistry",
    "get_agent_registry",

    # Orchestration
    "AgentOrchestrator",
    "WorkflowDefinition",
    "WorkflowStep",
    "WorkflowExecution",
    "WorkflowStatus",
    "ExecutionMode",
    "get_orchestrator",

    # Core Agents
    "SecurityAnalysisAgent",
    "IncidentResponseAgent",
    "IncidentPhase",
    "IncidentSeverity",
    "IncidentMetrics",
    "ImpactAssessment",
]
