"""
Incident Response Agent - Core Implementation

Manages the complete incident response lifecycle from detection through recovery,
generating comprehensive post-mortems, timelines, and corrective action plans.
"""

import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .framework import (
    BaseAgent,
    AgentCapability,
    AgentStatus,
    AgentContext,
    AgentInput,
    AgentOutput
)
from sentyr.config import SentyrConfig, get_config
from sentyr.logger import get_logger
from sentyr.jira_integration import JiraIssueManager, JiraAPIClient
from sentyr.models import AnalysisResult

logger = get_logger(__name__)


class IncidentPhase(Enum):
    """Incident response lifecycle phases"""
    DETECTION = "detection"
    ANALYSIS = "analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"


class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class IncidentMetrics:
    """Incident response metrics"""
    mttd: Optional[float] = None  # Mean Time To Detect (seconds)
    mttc: Optional[float] = None  # Mean Time To Contain (seconds)
    mttr: Optional[float] = None  # Mean Time To Recover (seconds)
    total_duration: Optional[float] = None  # Total incident duration (seconds)
    events_analyzed: int = 0
    systems_affected: int = 0
    data_sources_used: int = 0


@dataclass
class ImpactAssessment:
    """Business and operational impact assessment"""
    financial_loss: Optional[float] = None
    reputational_damage: str = "unknown"
    regulatory_exposure: List[str] = None
    downtime_hours: Optional[float] = None
    productivity_loss: Optional[float] = None
    data_compromised: bool = False
    systems_compromised: int = 0

    def __post_init__(self):
        if self.regulatory_exposure is None:
            self.regulatory_exposure = []


class IncidentResponseAgent(BaseAgent):
    """
    Incident Response Agent for managing security incidents.

    This agent orchestrates the complete incident response lifecycle,
    from initial detection through post-incident analysis and reporting.

    Capabilities:
    - Incident lifecycle management
    - Timeline reconstruction
    - Root cause analysis
    - Impact assessment
    - Post-mortem generation (BLUF, 5W1H)
    - Corrective action planning
    - Compliance reporting
    - AI explainability (XAI)
    """

    def __init__(self, config: Optional[SentyrConfig] = None):
        """Initialize Incident Response Agent"""
        if config is None:
            config = get_config()

        super().__init__(
            agent_id="incident-response-agent",
            agent_name="Incident Response Agent",
            agent_version="1.0.0",  # Updated for Jira integration
            capabilities=[
                AgentCapability.INCIDENT_RESPONSE,
                AgentCapability.ROOT_CAUSE_ANALYSIS,
                AgentCapability.TIMELINE_RECONSTRUCTION,
                AgentCapability.IMPACT_ASSESSMENT,
                AgentCapability.POST_MORTEM_GENERATION,
                AgentCapability.FORENSICS
            ],
            description="Comprehensive incident response management with automated post-mortem generation"
        )

        self.config = config

        # Initialize Jira integration (v1.0.0)
        self.jira_manager: Optional[JiraIssueManager] = None
        if config.jira_url and config.jira_username and config.jira_api_token and config.jira_project_key:
            try:
                api_client = JiraAPIClient(
                    base_url=config.jira_url,
                    username=config.jira_username,
                    api_token=config.jira_api_token
                )
                self.jira_manager = JiraIssueManager(
                    api_client=api_client,
                    project_key=config.jira_project_key,
                    auto_create_issues=config.jira_auto_create_issues,
                    default_issue_type="Security Incident"
                )
                logger.info("Jira integration initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Jira integration: {e}")
                self.jira_manager = None
        else:
            logger.info("Jira integration not configured")

        logger.info(f"Initialized {self.agent_name} v{self.agent_version}")

    async def execute(self, input_data: AgentInput) -> AgentOutput:
        """
        Execute incident response task.

        Supported tasks:
        - "lifecycle_management": Manage incident through all phases
        - "timeline_reconstruction": Build incident timeline
        - "root_cause_analysis": Determine root cause
        - "impact_assessment": Assess business impact
        - "post_mortem": Generate comprehensive post-mortem report
        - "corrective_actions": Generate corrective action plan

        Args:
            input_data: Input containing context, task, and parameters

        Returns:
            AgentOutput with incident response results
        """
        start_time = time.time()
        self._update_status(AgentStatus.RUNNING)

        try:
            # Validate input
            await self.validate_input(input_data)

            # Route to appropriate handler based on task
            task = input_data.task.lower().replace("_", " ")  # Normalize underscores to spaces

            if "timeline" in task:
                output = await self._reconstruct_timeline(input_data, start_time)
            elif "root cause" in task or "rca" in task:
                output = await self._perform_root_cause_analysis(input_data, start_time)
            elif "impact" in task:
                output = await self._assess_impact(input_data, start_time)
            elif "post mortem" in task or "after action" in task or "postmortem" in task:
                output = await self._generate_post_mortem(input_data, start_time)
            elif "corrective" in task or "remediation" in task:
                output = await self._generate_corrective_actions(input_data, start_time)
            elif "lifecycle" in task or "manage" in task:
                output = await self._manage_incident_lifecycle(input_data, start_time)
            else:
                # Default: comprehensive incident response
                output = await self._comprehensive_incident_response(input_data, start_time)

            self._update_status(AgentStatus.COMPLETED)
            logger.info(f"Incident response task completed in {output.execution_time:.2f}s")

            return output

        except Exception as e:
            self._update_status(AgentStatus.FAILED)
            logger.error(f"Incident response failed: {e}")

            return AgentOutput(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                results={},
                confidence=0.0,
                reasoning=[f"Incident response failed: {str(e)}"],
                data_sources_used=[],
                recommendations=[],
                next_actions=["Review error logs", "Retry with valid input"],
                audit_trail=[],
                execution_time=time.time() - start_time,
                error=str(e)
            )

    async def validate_input(self, input_data: AgentInput) -> bool:
        """Validate input data"""
        if not input_data.context:
            raise ValueError("AgentContext is required")

        if not input_data.context.incident_id:
            raise ValueError("Incident ID is required in context")

        return True

    async def _reconstruct_timeline(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Reconstruct incident timeline from all available data sources.

        Correlates events across logs, EDR, network, cloud, and human actions
        to build a comprehensive chronological view of the incident.
        """
        context = input_data.context

        logger.info(f"Reconstructing timeline for incident {context.incident_id}")

        # Collect all events from data sources
        all_events = []

        # Extract events from data sources
        for source_name, source_data in context.data_sources.items():
            if isinstance(source_data, list):
                for event in source_data:
                    all_events.append({
                        "timestamp": self._extract_timestamp(event),
                        "source": source_name,
                        "event_type": "detection",
                        "actor": "system",
                        "action": self._extract_action(event),
                        "effect": self._extract_effect(event),
                        "confidence": 0.8,
                        "evidence": [str(event)]
                    })

        # Add existing timeline events
        all_events.extend(context.timeline)

        # Add actions taken
        for action in context.actions_taken:
            all_events.append({
                "timestamp": action.get("timestamp", action.get("recorded_at")),
                "source": "incident_response",
                "event_type": "action",
                "actor": action.get("actor", "analyst"),
                "action": action.get("action", "unknown"),
                "effect": action.get("effect", "unknown"),
                "confidence": 1.0,
                "evidence": [str(action)]
            })

        # Sort by timestamp
        all_events.sort(key=lambda x: x.get("timestamp", ""))

        # Update context timeline
        context.timeline = all_events

        # Create audit entry
        audit_entry = self._create_audit_entry(
            action="timeline_reconstruction",
            data_sources=list(context.data_sources.keys()),
            reasoning=[
                f"Collected {len(all_events)} events from {len(context.data_sources)} data sources",
                "Correlated events across system logs, EDR, network, and human actions",
                "Sorted chronologically to establish incident sequence"
            ],
            confidence=0.85,
            decision=f"Reconstructed timeline with {len(all_events)} events"
        )
        context.add_audit_entry(self.agent_id, audit_entry)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "timeline": all_events,
                "total_events": len(all_events),
                "data_sources": len(context.data_sources),
                "time_span": self._calculate_time_span(all_events)
            },
            confidence=0.85,
            reasoning=[
                f"Reconstructed timeline from {len(context.data_sources)} data sources",
                f"Identified {len(all_events)} events",
                "Correlated system events with human actions"
            ],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=[
                {"action": "Review timeline for gaps", "priority": "medium"},
                {"action": "Validate event correlation", "priority": "high"}
            ],
            next_actions=["Perform root cause analysis", "Assess impact"],
            audit_trail=[audit_entry],
            execution_time=time.time() - start_time
        )

    async def _perform_root_cause_analysis(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Perform root cause analysis to determine how the incident occurred.

        Uses timeline, findings, and threat intelligence to trace back
        to the initial compromise or vulnerability.
        """
        context = input_data.context

        logger.info(f"Performing root cause analysis for incident {context.incident_id}")

        # Analyze timeline for initial access
        initial_events = []
        if context.timeline:
            # Get earliest events
            sorted_timeline = sorted(context.timeline, key=lambda x: x.get("timestamp", ""))
            initial_events = sorted_timeline[:5]  # First 5 events

        # Analyze findings for attack vectors
        attack_vectors = []
        for finding in context.findings:
            if "attack_chain" in finding.get("results", {}):
                attack_chain = finding["results"]["attack_chain"]
                if attack_chain:
                    attack_vectors.append(attack_chain[0])  # First step in chain

        # Determine root cause
        root_cause = self._determine_root_cause(initial_events, attack_vectors, context)

        # Create audit entry
        audit_entry = self._create_audit_entry(
            action="root_cause_analysis",
            data_sources=list(context.data_sources.keys()),
            reasoning=[
                f"Analyzed {len(context.timeline)} timeline events",
                f"Examined {len(context.findings)} security findings",
                f"Identified {len(attack_vectors)} attack vectors",
                "Traced incident back to initial compromise"
            ],
            confidence=root_cause["confidence"],
            decision=root_cause["description"],
            alternatives=root_cause.get("alternatives", [])
        )
        context.add_audit_entry(self.agent_id, audit_entry)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "root_cause": root_cause,
                "initial_events": initial_events,
                "attack_vectors": attack_vectors
            },
            confidence=root_cause["confidence"],
            reasoning=root_cause["reasoning"],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=root_cause.get("recommendations", []),
            next_actions=["Generate corrective action plan", "Update security controls"],
            audit_trail=[audit_entry],
            execution_time=time.time() - start_time
        )

    async def _assess_impact(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Assess business and operational impact of the incident.

        Calculates MTTD, MTTC, MTTR and assesses financial, reputational,
        and regulatory impact.
        """
        context = input_data.context

        logger.info(f"Assessing impact for incident {context.incident_id}")

        # Calculate metrics
        metrics = self._calculate_incident_metrics(context)

        # Assess business impact
        impact = self._assess_business_impact(context, metrics)

        # Store in context
        context.incident_metadata["metrics"] = {
            "mttd": metrics.mttd,
            "mttc": metrics.mttc,
            "mttr": metrics.mttr,
            "total_duration": metrics.total_duration,
            "events_analyzed": metrics.events_analyzed,
            "systems_affected": metrics.systems_affected
        }

        context.incident_metadata["impact"] = {
            "financial_loss": impact.financial_loss,
            "reputational_damage": impact.reputational_damage,
            "regulatory_exposure": impact.regulatory_exposure,
            "downtime_hours": impact.downtime_hours,
            "data_compromised": impact.data_compromised,
            "systems_compromised": impact.systems_compromised
        }

        # Create audit entry
        audit_entry = self._create_audit_entry(
            action="impact_assessment",
            data_sources=list(context.data_sources.keys()),
            reasoning=[
                f"Calculated incident metrics: MTTD={metrics.mttd}s, MTTC={metrics.mttc}s, MTTR={metrics.mttr}s",
                f"Assessed {metrics.systems_affected} affected systems",
                f"Estimated financial impact: ${impact.financial_loss or 0}",
                f"Regulatory exposure: {', '.join(impact.regulatory_exposure) if impact.regulatory_exposure else 'None'}"
            ],
            confidence=0.75,
            decision=f"Impact severity: {impact.reputational_damage}"
        )
        context.add_audit_entry(self.agent_id, audit_entry)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "metrics": {
                    "mttd_seconds": metrics.mttd,
                    "mttc_seconds": metrics.mttc,
                    "mttr_seconds": metrics.mttr,
                    "total_duration_seconds": metrics.total_duration,
                    "mttd_hours": metrics.mttd / 3600 if metrics.mttd else None,
                    "mttc_hours": metrics.mttc / 3600 if metrics.mttc else None,
                    "mttr_hours": metrics.mttr / 3600 if metrics.mttr else None,
                    "total_duration_hours": metrics.total_duration / 3600 if metrics.total_duration else None
                },
                "impact": {
                    "financial_loss": impact.financial_loss,
                    "reputational_damage": impact.reputational_damage,
                    "regulatory_exposure": impact.regulatory_exposure,
                    "downtime_hours": impact.downtime_hours,
                    "productivity_loss": impact.productivity_loss,
                    "data_compromised": impact.data_compromised,
                    "systems_compromised": impact.systems_compromised
                }
            },
            confidence=0.75,
            reasoning=[
                f"Analyzed {metrics.events_analyzed} events",
                f"Identified {metrics.systems_affected} affected systems",
                "Calculated incident response metrics",
                "Assessed business and regulatory impact"
            ],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=[
                {"action": "Review incident response times", "priority": "high"},
                {"action": "Assess need for breach notification", "priority": "critical" if impact.data_compromised else "low"}
            ],
            next_actions=["Generate post-mortem report", "Plan corrective actions"],
            audit_trail=[audit_entry],
            execution_time=time.time() - start_time
        )

    async def _generate_post_mortem(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Generate comprehensive post-mortem report.

        Includes BLUF, 5W1H, executive summary, technical analysis,
        timeline, root cause, impact assessment, and recommendations.
        """
        context = input_data.context

        logger.info(f"Generating post-mortem for incident {context.incident_id}")

        # Generate BLUF (Bottom Line Up Front)
        bluf = self._generate_bluf(context)

        # Generate 5W1H
        five_w1h = self._generate_5w1h(context)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(context)

        # Generate technical analysis
        technical_analysis = self._generate_technical_analysis(context)

        # Compile post-mortem
        post_mortem = {
            "incident_id": context.incident_id,
            "generated_at": datetime.utcnow().isoformat(),
            "blu": bluf,
            "five_w1h": five_w1h,
            "executive_summary": executive_summary,
            "technical_analysis": technical_analysis,
            "timeline": context.timeline,
            "root_cause": context.incident_metadata.get("root_cause"),
            "impact_assessment": context.incident_metadata.get("impact"),
            "metrics": context.incident_metadata.get("metrics"),
            "recommendations": self._compile_recommendations(context),
            "lessons_learned": self._extract_lessons_learned(context)
        }

        # Create audit entry
        audit_entry = self._create_audit_entry(
            action="post_mortem_generation",
            data_sources=list(context.data_sources.keys()),
            reasoning=[
                "Compiled comprehensive incident analysis",
                "Generated BLUF and 5W1H analysis",
                f"Included {len(context.timeline)} timeline events",
                f"Synthesized {len(context.findings)} security findings"
            ],
            confidence=0.9,
            decision="Post-mortem report generated successfully"
        )
        context.add_audit_entry(self.agent_id, audit_entry)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={"post_mortem": post_mortem},
            confidence=0.9,
            reasoning=[
                "Generated comprehensive post-mortem report",
                "Included BLUF, 5W1H, and executive summary",
                "Compiled technical analysis and timeline",
                "Provided actionable recommendations"
            ],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=post_mortem["recommendations"],
            next_actions=["Review with stakeholders", "Implement corrective actions", "Update runbooks"],
            audit_trail=[audit_entry],
            execution_time=time.time() - start_time
        )

    async def _generate_corrective_actions(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Generate corrective action plan.

        Includes technical remediation, process improvements, and training needs.
        """
        context = input_data.context

        logger.info(f"Generating corrective actions for incident {context.incident_id}")

        # Generate technical remediation steps
        technical_remediation = self._generate_technical_remediation(context)

        # Generate process improvements
        process_improvements = self._generate_process_improvements(context)

        # Generate training needs
        training_needs = self._generate_training_needs(context)

        # Compile corrective action plan
        corrective_actions = {
            "incident_id": context.incident_id,
            "generated_at": datetime.utcnow().isoformat(),
            "technical_remediation": technical_remediation,
            "process_improvements": process_improvements,
            "training_needs": training_needs,
            "priority_matrix": self._create_priority_matrix(
                technical_remediation,
                process_improvements,
                training_needs
            )
        }

        # Create audit entry
        audit_entry = self._create_audit_entry(
            action="corrective_action_planning",
            data_sources=list(context.data_sources.keys()),
            reasoning=[
                f"Generated {len(technical_remediation)} technical remediation steps",
                f"Identified {len(process_improvements)} process improvements",
                f"Defined {len(training_needs)} training needs",
                "Prioritized actions by impact and urgency"
            ],
            confidence=0.85,
            decision="Corrective action plan generated"
        )
        context.add_audit_entry(self.agent_id, audit_entry)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={"corrective_actions": corrective_actions},
            confidence=0.85,
            reasoning=[
                "Generated comprehensive corrective action plan",
                "Prioritized actions by impact and urgency",
                "Included technical, process, and training improvements"
            ],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=technical_remediation + process_improvements,
            next_actions=["Assign ownership", "Set deadlines", "Track implementation"],
            audit_trail=[audit_entry],
            execution_time=time.time() - start_time
        )

    async def _manage_incident_lifecycle(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Manage incident through all lifecycle phases"""
        context = input_data.context

        logger.info(f"Managing incident lifecycle for {context.incident_id}")

        # Determine current phase
        current_phase = self._determine_current_phase(context)

        # Execute phase-specific actions
        phase_results = await self._execute_phase_actions(context, current_phase)

        # Update incident metadata
        context.incident_metadata["current_phase"] = current_phase.value
        context.incident_metadata["phase_results"] = phase_results

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "current_phase": current_phase.value,
                "phase_results": phase_results
            },
            confidence=0.8,
            reasoning=[f"Incident in {current_phase.value} phase"],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=[],
            next_actions=[f"Continue {current_phase.value} activities"],
            audit_trail=[],
            execution_time=time.time() - start_time
        )

    async def _comprehensive_incident_response(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Perform comprehensive incident response.

        Executes all IR capabilities: timeline, RCA, impact, post-mortem, corrective actions.
        """
        context = input_data.context

        logger.info(f"Performing comprehensive incident response for {context.incident_id}")

        # Execute all IR tasks
        timeline_output = await self._reconstruct_timeline(input_data, time.time())
        rca_output = await self._perform_root_cause_analysis(input_data, time.time())
        impact_output = await self._assess_impact(input_data, time.time())
        post_mortem_output = await self._generate_post_mortem(input_data, time.time())
        corrective_output = await self._generate_corrective_actions(input_data, time.time())

        # Aggregate results
        comprehensive_results = {
            "timeline": timeline_output.results,
            "root_cause_analysis": rca_output.results,
            "impact_assessment": impact_output.results,
            "post_mortem": post_mortem_output.results,
            "corrective_actions": corrective_output.results
        }

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results=comprehensive_results,
            confidence=0.85,
            reasoning=[
                "Completed comprehensive incident response",
                "Generated timeline, RCA, impact assessment, post-mortem, and corrective actions"
            ],
            data_sources_used=list(context.data_sources.keys()),
            recommendations=corrective_output.recommendations,
            next_actions=["Review comprehensive report", "Implement corrective actions"],
            audit_trail=[],
            execution_time=time.time() - start_time
        )

    # Helper methods

    def _extract_timestamp(self, event: Any) -> str:
        """Extract timestamp from event"""
        if isinstance(event, dict):
            return event.get("timestamp", event.get("time", datetime.utcnow().isoformat()))
        return datetime.utcnow().isoformat()

    def _extract_action(self, event: Any) -> str:
        """Extract action from event"""
        if isinstance(event, dict):
            return event.get("action", event.get("title", event.get("description", "unknown")))
        return str(event)

    def _extract_effect(self, event: Any) -> str:
        """Extract effect from event"""
        if isinstance(event, dict):
            return event.get("effect", event.get("impact", "unknown"))
        return "unknown"

    def _calculate_time_span(self, events: List[Dict]) -> Dict[str, Any]:
        """Calculate time span of events"""
        if not events:
            return {"start": None, "end": None, "duration_seconds": 0}

        timestamps = [e.get("timestamp") for e in events if e.get("timestamp")]
        if not timestamps:
            return {"start": None, "end": None, "duration_seconds": 0}

        start = min(timestamps)
        end = max(timestamps)

        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            duration = (end_dt - start_dt).total_seconds()
        except (ValueError, AttributeError, TypeError) as e:
            logger.warning(f"Failed to parse duration: {e}")
            duration = 0

        return {
            "start": start,
            "end": end,
            "duration_seconds": duration,
            "duration_hours": duration / 3600
        }

    def _determine_root_cause(
        self,
        initial_events: List[Dict],
        attack_vectors: List[str],
        context: AgentContext
    ) -> Dict[str, Any]:
        """
        Determine root cause from evidence using structured decision framework.

        Decision Framework:
        1. Evidence Assessment: Evaluate quality and completeness of available data
        2. Pattern Analysis: Identify common attack patterns and techniques
        3. Timeline Analysis: Trace back to initial compromise vector
        4. Alternative Hypothesis Testing: Consider and rule out alternative explanations
        5. Confidence Scoring: Assign confidence based on evidence strength
        6. Recommendation Generation: Provide actionable remediation steps
        """

        # Phase 1: Evidence Assessment
        evidence_quality = self._assess_evidence_quality(initial_events, attack_vectors, context)

        if evidence_quality["score"] < 0.3:
            return {
                "description": "Insufficient data to determine root cause with confidence",
                "category": "unknown",
                "confidence": evidence_quality["score"],
                "reasoning": [
                    f"Evidence quality score: {evidence_quality['score']:.2f} (below threshold)",
                    f"Available events: {len(initial_events)}",
                    f"Identified attack vectors: {len(attack_vectors)}",
                    "Recommendation: Gather additional forensic data before proceeding"
                ],
                "evidence_gaps": evidence_quality["gaps"],
                "recommendations": [
                    {"action": "Enable comprehensive logging on affected systems", "priority": "critical", "timeframe": "immediate"},
                    {"action": "Collect memory dumps from compromised hosts", "priority": "high", "timeframe": "0-1h"},
                    {"action": "Review data retention policies", "priority": "medium", "timeframe": "1-4h"},
                    {"action": "Query threat intelligence feeds for related indicators", "priority": "high", "timeframe": "0-1h"}
                ],
                "decision_rationale": "Without sufficient evidence, any root cause determination would be speculative and could lead to ineffective remediation."
            }

        # Phase 2: Pattern Analysis
        attack_patterns = self._analyze_attack_patterns(initial_events, attack_vectors, context)

        # Phase 3: Root Cause Determination with Chain-of-Thought
        root_cause = self._determine_root_cause_with_cot(
            initial_events,
            attack_vectors,
            attack_patterns,
            context
        )

        return root_cause

    def _assess_evidence_quality(
        self,
        initial_events: List[Dict],
        attack_vectors: List[str],
        context: AgentContext
    ) -> Dict[str, Any]:
        """Assess quality and completeness of available evidence."""
        score = 0.0
        gaps = []

        # Check for timeline events
        if len(initial_events) >= 5:
            score += 0.3
        elif len(initial_events) >= 1:
            score += 0.15
        else:
            gaps.append("No initial timeline events available")

        # Check for attack vectors
        if len(attack_vectors) >= 3:
            score += 0.3
        elif len(attack_vectors) >= 1:
            score += 0.15
        else:
            gaps.append("No clear attack vectors identified")

        # Check for findings
        if len(context.findings) >= 3:
            score += 0.2
        elif len(context.findings) >= 1:
            score += 0.1
        else:
            gaps.append("Limited security findings available")

        # Check for IOCs
        if len(context.iocs) >= 5:
            score += 0.2
        elif len(context.iocs) >= 1:
            score += 0.1
        else:
            gaps.append("Few indicators of compromise identified")

        return {"score": score, "gaps": gaps}

    def _analyze_attack_patterns(
        self,
        initial_events: List[Dict],
        attack_vectors: List[str],
        context: AgentContext
    ) -> Dict[str, Any]:
        """Analyze events and vectors for common attack patterns."""
        patterns = {
            "credential_based": False,
            "vulnerability_exploitation": False,
            "social_engineering": False,
            "supply_chain": False,
            "insider_threat": False,
            "lateral_movement": False,
            "data_exfiltration": False
        }

        evidence_all = str(initial_events) + str(attack_vectors) + str(context.findings)
        evidence_lower = evidence_all.lower()

        # Detect credential-based attacks
        if any(keyword in evidence_lower for keyword in ["credential", "password", "brute force", "login", "authentication"]):
            patterns["credential_based"] = True

        # Detect vulnerability exploitation
        if any(keyword in evidence_lower for keyword in ["exploit", "vulnerability", "cve-", "remote code execution", "rce"]):
            patterns["vulnerability_exploitation"] = True

        # Detect social engineering
        if any(keyword in evidence_lower for keyword in ["phishing", "spear phish", "social engineering", "malicious email"]):
            patterns["social_engineering"] = True

        # Detect supply chain
        if any(keyword in evidence_lower for keyword in ["supply chain", "third party", "vendor", "dependency"]):
            patterns["supply_chain"] = True

        # Detect insider threat
        if any(keyword in evidence_lower for keyword in ["insider", "privileged user", "abuse of access"]):
            patterns["insider_threat"] = True

        # Detect lateral movement
        if any(keyword in evidence_lower for keyword in ["lateral movement", "pass the hash", "credential dumping", "mimikatz"]):
            patterns["lateral_movement"] = True

        # Detect data exfiltration
        if any(keyword in evidence_lower for keyword in ["exfiltration", "data transfer", "file download", "upload"]):
            patterns["data_exfiltration"] = True

        return patterns

    def _determine_root_cause_with_cot(
        self,
        initial_events: List[Dict],
        attack_vectors: List[str],
        attack_patterns: Dict[str, bool],
        context: AgentContext
    ) -> Dict[str, Any]:
        """Determine root cause using chain-of-thought reasoning."""

        reasoning_chain = []
        alternatives = []

        # Step 1: Initial hypothesis generation
        reasoning_chain.append(
            f"INITIAL ASSESSMENT: Analyzing {len(initial_events)} initial events and "
            f"{len(attack_vectors)} attack vectors across {len(context.findings)} findings"
        )

        active_patterns = [k for k, v in attack_patterns.items() if v]
        reasoning_chain.append(
            f"PATTERN DETECTION: Identified {len(active_patterns)} attack patterns: {', '.join(active_patterns)}"
        )

        # Step 2: Credential-based compromise
        if attack_patterns["credential_based"]:
            reasoning_chain.append(
                "CREDENTIAL ANALYSIS: Strong indicators of credential-based compromise detected"
            )
            reasoning_chain.append(
                "EVIDENCE: Attack chain shows authentication events, failed login attempts, or credential abuse"
            )

            # Check for social engineering
            if attack_patterns["social_engineering"]:
                confidence = 0.90
                reasoning_chain.append(
                    "ATTRIBUTION: Phishing attack likely obtained credentials (high confidence)"
                )
                alternatives.append({
                    "hypothesis": "Credential stuffing from breach database",
                    "confidence": 0.60,
                    "rationale": "Could explain credential compromise without phishing indicators"
                })
                alternatives.append({
                    "hypothesis": "Insider threat or malicious employee",
                    "confidence": 0.30,
                    "rationale": "Less likely given external attack indicators"
                })
            else:
                confidence = 0.85
                reasoning_chain.append(
                    "ATTRIBUTION: Credential compromise via brute force or credential stuffing (high confidence)"
                )
                alternatives.append({
                    "hypothesis": "Phishing attack (low indicators detected)",
                    "confidence": 0.45,
                    "rationale": "Some credential theft but limited phishing evidence"
                })

            reasoning_chain.append(
                "IMPACT ANALYSIS: Compromised credentials enabled initial access and potential privilege escalation"
            )

            return {
                "description": "Compromised credentials enabled initial access to systems",
                "category": "credential_compromise",
                "confidence": confidence,
                "reasoning": reasoning_chain,
                "evidence_summary": {
                    "credential_indicators": True,
                    "social_engineering_indicators": attack_patterns["social_engineering"],
                    "lateral_movement": attack_patterns["lateral_movement"],
                    "total_events_analyzed": len(initial_events) + len(attack_vectors)
                },
                "attack_kill_chain": [
                    "Initial Access: Credential Compromise",
                    "Execution: Authenticated Login" if attack_patterns["lateral_movement"] else "Execution: Single System Access",
                    "Persistence: Unknown (requires further investigation)",
                    "Privilege Escalation: Possible" if attack_patterns["lateral_movement"] else "Not Observed"
                ],
                "recommendations": [
                    {
                        "action": "Force password reset for all potentially compromised accounts",
                        "priority": "critical",
                        "timeframe": "immediate",
                        "owner": "Identity & Access Management",
                        "rationale": "Immediately revoke compromised credentials to prevent continued access"
                    },
                    {
                        "action": "Implement MFA for all user accounts, especially privileged accounts",
                        "priority": "critical",
                        "timeframe": "0-24h",
                        "owner": "IT Security",
                        "rationale": "MFA would have prevented this attack vector"
                    },
                    {
                        "action": "Review authentication logs for all successful logins from affected accounts",
                        "priority": "high",
                        "timeframe": "0-4h",
                        "owner": "SOC",
                        "rationale": "Identify scope of unauthorized access"
                    },
                    {
                        "action": "Deploy credential monitoring and breach detection tools",
                        "priority": "high",
                        "timeframe": "1-7 days",
                        "owner": "Security Engineering",
                        "rationale": "Proactively detect future credential compromises"
                    },
                    {
                        "action": "Conduct security awareness training on phishing and password hygiene",
                        "priority": "medium",
                        "timeframe": "1-4 weeks",
                        "owner": "Security Awareness Team",
                        "rationale": "Reduce likelihood of future credential compromise"
                    }
                ],
                "alternatives": alternatives,
                "decision_rationale": f"Root cause determined with {confidence:.0%} confidence based on {len(reasoning_chain)} lines of evidence. Credential compromise is the most likely initial access vector given the observed attack patterns and available evidence."
            }

        # Step 3: Vulnerability exploitation
        if attack_patterns["vulnerability_exploitation"]:
            confidence = 0.85
            reasoning_chain.append(
                "VULNERABILITY ANALYSIS: Evidence of vulnerability exploitation detected"
            )
            reasoning_chain.append(
                "EVIDENCE: Attack chain shows exploit indicators, CVE references, or remote code execution"
            )

            alternatives.append({
                "hypothesis": "Zero-day exploitation",
                "confidence": 0.40,
                "rationale": "Possible if no known CVE matches observed behavior"
            })

            return {
                "description": "Vulnerability exploitation enabled initial system compromise",
                "category": "vulnerability_exploitation",
                "confidence": confidence,
                "reasoning": reasoning_chain,
                "recommendations": [
                    {
                        "action": "Identify and patch exploited vulnerability immediately",
                        "priority": "critical",
                        "timeframe": "immediate",
                        "owner": "Patch Management",
                        "rationale": "Prevent continued exploitation"
                    },
                    {
                        "action": "Deploy virtual patching or WAF rules if patch unavailable",
                        "priority": "critical",
                        "timeframe": "0-4h",
                        "owner": "Security Engineering",
                        "rationale": "Mitigate risk while permanent fix is deployed"
                    },
                    {
                        "action": "Scan all systems for same vulnerability",
                        "priority": "high",
                        "timeframe": "0-24h",
                        "owner": "Vulnerability Management",
                        "rationale": "Identify and remediate organization-wide exposure"
                    },
                    {
                        "action": "Implement automated vulnerability scanning and patching",
                        "priority": "high",
                        "timeframe": "1-4 weeks",
                        "owner": "IT Operations",
                        "rationale": "Prevent future exploitation of unpatched systems"
                    }
                ],
                "alternatives": alternatives,
                "decision_rationale": f"Root cause determined with {confidence:.0%} confidence. Vulnerability exploitation is the primary initial access vector."
            }

        # Default: Insufficient specific indicators
        reasoning_chain.append(
            "CONCLUSION: No dominant attack pattern detected - requires additional investigation"
        )

        return {
            "description": "Root cause analysis in progress - preliminary patterns identified",
            "category": "under_investigation",
            "confidence": 0.6,
            "reasoning": reasoning_chain,
            "patterns_detected": active_patterns,
            "recommendations": [
                {"action": "Continue forensic investigation to identify initial access vector", "priority": "high", "timeframe": "0-4h"},
                {"action": "Collect additional logs from affected systems", "priority": "high", "timeframe": "0-1h"},
                {"action": "Query threat intelligence for similar attack patterns", "priority": "medium", "timeframe": "1-4h"}
            ],
            "decision_rationale": "Available evidence does not conclusively point to a single root cause. Recommend continued investigation before implementing remediation."
        }

    def _calculate_incident_metrics(self, context: AgentContext) -> IncidentMetrics:
        """Calculate incident response metrics"""
        metrics = IncidentMetrics()

        if context.timeline:
            metrics.events_analyzed = len(context.timeline)

            # Extract key timestamps
            timestamps = self._extract_key_timestamps(context.timeline)

            # Calculate time-based metrics
            self._calculate_time_metrics(metrics, timestamps, context.timeline)

            # Calculate total duration
            time_span = self._calculate_time_span(context.timeline)
            metrics.total_duration = time_span.get("duration_seconds", 0)

        # Count affected systems and data sources
        metrics.systems_affected = len(context.affected_assets)
        metrics.data_sources_used = len(context.data_sources)

        return metrics

    def _extract_key_timestamps(self, timeline: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
        """Extract detection, containment, and recovery timestamps from timeline."""
        timestamps = {
            "detection": None,
            "containment": None,
            "recovery": None
        }

        for event in timeline:
            event_type = event.get("event_type", "")
            timestamp = event.get("timestamp")

            if "detection" in event_type and not timestamps["detection"]:
                timestamps["detection"] = timestamp
            elif "contain" in event_type and not timestamps["containment"]:
                timestamps["containment"] = timestamp
            elif "recover" in event_type and not timestamps["recovery"]:
                timestamps["recovery"] = timestamp

        return timestamps

    def _calculate_time_metrics(
        self,
        metrics: IncidentMetrics,
        timestamps: Dict[str, Optional[str]],
        timeline: List[Dict[str, Any]]
    ):
        """Calculate MTTD, MTTC, and MTTR metrics."""
        # Calculate MTTD (Mean Time To Detect)
        if timestamps["detection"] and timeline:
            first_event_time = timeline[0].get("timestamp")
            if first_event_time:
                mttd = self._calculate_time_delta(first_event_time, timestamps["detection"])
                if mttd is not None:
                    metrics.mttd = mttd

        # Calculate MTTC (Mean Time To Contain)
        if timestamps["containment"] and timestamps["detection"]:
            mttc = self._calculate_time_delta(timestamps["detection"], timestamps["containment"])
            if mttc is not None:
                metrics.mttc = mttc

        # Calculate MTTR (Mean Time To Recover)
        if timestamps["recovery"] and timestamps["containment"]:
            mttr = self._calculate_time_delta(timestamps["containment"], timestamps["recovery"])
            if mttr is not None:
                metrics.mttr = mttr

    def _calculate_time_delta(self, start_time: str, end_time: str) -> Optional[float]:
        """Calculate time delta in seconds between two ISO timestamps."""
        try:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            return (end_dt - start_dt).total_seconds()
        except (ValueError, AttributeError, TypeError) as e:
            logger.debug(f"Failed to calculate time delta: {e}")
            return None

    def _assess_business_impact(
        self,
        context: AgentContext,
        metrics: IncidentMetrics
    ) -> ImpactAssessment:
        """Assess business impact"""
        impact = ImpactAssessment()

        # Estimate financial loss based on downtime
        if metrics.total_duration:
            downtime_hours = metrics.total_duration / 3600
            impact.downtime_hours = downtime_hours

            # Simple estimation: $10,000 per hour of downtime
            impact.financial_loss = downtime_hours * 10000

        # Assess reputational damage based on severity
        severity = context.incident_metadata.get("severity", "medium")
        if severity == "critical":
            impact.reputational_damage = "severe"
        elif severity == "high":
            impact.reputational_damage = "moderate"
        else:
            impact.reputational_damage = "minimal"

        # Check for data compromise
        for finding in context.findings:
            if "data" in str(finding).lower() and "exfiltrat" in str(finding).lower():
                impact.data_compromised = True
                break

        # Determine regulatory exposure
        if impact.data_compromised:
            impact.regulatory_exposure = ["GDPR", "CCPA", "HIPAA"]  # Depends on data type

        # Count compromised systems
        impact.systems_compromised = metrics.systems_affected

        return impact

    def _generate_bluf(self, context: AgentContext) -> str:
        """Generate Bottom Line Up Front summary"""
        incident_id = context.incident_id
        severity = context.incident_metadata.get("severity", "unknown")
        systems_affected = len(context.affected_assets)

        return (
            f"Incident {incident_id} ({severity} severity) affected {systems_affected} systems. "
            "Root cause identified, containment achieved, recovery in progress. "
            "Corrective actions defined to prevent recurrence."
        )

    def _generate_5w1h(self, context: AgentContext) -> Dict[str, str]:
        """Generate 5W1H analysis"""
        return {
            "who": "Threat actor (attribution in progress)",
            "what": f"Security incident {context.incident_id}",
            "when": context.created_at.isoformat() if hasattr(context.created_at, 'isoformat') else str(context.created_at),
            "where": f"{len(context.affected_assets)} systems affected",
            "why": context.incident_metadata.get("root_cause", {}).get("description", "Under investigation"),
            "how": "Attack chain analysis in progress"
        }

    def _generate_executive_summary(self, context: AgentContext) -> str:
        """Generate executive summary"""
        return (
            f"This report provides a comprehensive analysis of incident {context.incident_id}. "
            f"The incident was detected on {context.created_at} and affected {len(context.affected_assets)} systems. "
            "Our investigation identified the root cause and implemented corrective actions to prevent recurrence. "
            "All affected systems have been remediated and returned to normal operations."
        )

    def _generate_technical_analysis(self, context: AgentContext) -> str:
        """Generate technical analysis"""
        findings_count = len(context.findings)
        iocs_count = len(context.iocs)
        timeline_events = len(context.timeline)

        return (
            f"Technical analysis identified {findings_count} security findings across {timeline_events} events. "
            f"Extracted {iocs_count} indicators of compromise for threat intelligence. "
            "Detailed timeline reconstruction shows the complete attack sequence. "
            "Root cause analysis traced the incident to initial compromise vector."
        )

    def _compile_recommendations(self, context: AgentContext) -> List[Dict[str, Any]]:
        """Compile all recommendations"""
        recommendations = []

        # Extract from root cause
        root_cause = context.incident_metadata.get("root_cause", {})
        if root_cause.get("recommendations"):
            recommendations.extend(root_cause["recommendations"])

        # Add general recommendations
        recommendations.append({
            "action": "Update incident response playbooks",
            "priority": "medium",
            "category": "process"
        })

        recommendations.append({
            "action": "Conduct tabletop exercise",
            "priority": "low",
            "category": "training"
        })

        return recommendations

    def _extract_lessons_learned(self, context: AgentContext) -> List[str]:
        """Extract lessons learned"""
        return [
            "Improved detection capabilities needed",
            "Faster containment procedures required",
            "Enhanced logging and monitoring recommended",
            "Regular security training essential"
        ]

    def _generate_technical_remediation(self, context: AgentContext) -> List[Dict[str, Any]]:
        """
        Generate technical remediation steps based on root cause and attack patterns.

        Decision Logic:
        1. Extract root cause category from context
        2. Identify attack patterns and techniques
        3. Generate specific, actionable remediation steps
        4. Prioritize by impact and urgency
        5. Assign ownership and realistic timelines
        """
        remediation_steps = []

        # Get root cause from context
        root_cause = context.incident_metadata.get("root_cause", {})
        root_cause_category = root_cause.get("category", "unknown")

        # Get MITRE techniques if available
        mitre_techniques = []
        for finding in context.findings:
            if isinstance(finding, dict) and "mitre_techniques" in finding.get("results", {}):
                mitre_techniques.extend(finding["results"]["mitre_techniques"])

        # Category-specific remediation
        if root_cause_category == "credential_compromise":
            remediation_steps.extend([
                {
                    "action": "Force password reset for all compromised accounts immediately",
                    "priority": "critical",
                    "category": "technical",
                    "owner": "Identity & Access Management",
                    "timeline": "immediate (0-1h)",
                    "rationale": "Revoke compromised credentials to prevent ongoing unauthorized access",
                    "success_criteria": "All affected accounts locked/reset within 1 hour",
                    "estimated_effort": "2-4 hours"
                },
                {
                    "action": "Enable MFA for all user accounts, prioritize privileged accounts",
                    "priority": "critical",
                    "category": "technical",
                    "owner": "IT Security",
                    "timeline": "0-24h for critical accounts, 1 week for all accounts",
                    "rationale": "Prevent future credential-based attacks",
                    "success_criteria": "100% MFA enrollment for privileged users, 80% for all users",
                    "estimated_effort": "40-80 hours"
                },
                {
                    "action": "Deploy password breach monitoring and alerting",
                    "priority": "high",
                    "category": "technical",
                    "owner": "Security Engineering",
                    "timeline": "1-2 weeks",
                    "rationale": "Proactively detect compromised credentials",
                    "success_criteria": "Monitoring active for all corporate accounts",
                    "estimated_effort": "16-24 hours"
                }
            ])

        if root_cause_category == "vulnerability_exploitation":
            remediation_steps.extend([
                {
                    "action": "Identify and patch exploited vulnerability on all affected systems",
                    "priority": "critical",
                    "category": "technical",
                    "owner": "Patch Management",
                    "timeline": "immediate (0-4h)",
                    "rationale": "Eliminate attack vector immediately",
                    "success_criteria": "Vulnerable systems patched or isolated within 4 hours",
                    "estimated_effort": "4-8 hours"
                },
                {
                    "action": "Scan entire environment for same vulnerability",
                    "priority": "critical",
                    "category": "technical",
                    "owner": "Vulnerability Management",
                    "timeline": "0-24h",
                    "rationale": "Identify and remediate organization-wide exposure",
                    "success_criteria": "Full vulnerability scan completed, remediation plan created",
                    "estimated_effort": "8-16 hours"
                },
                {
                    "action": "Implement virtual patching or WAF rules for exploited vulnerability",
                    "priority": "high",
                    "category": "technical",
                    "owner": "Security Engineering",
                    "timeline": "0-4h",
                    "rationale": "Provide temporary protection while patching is in progress",
                    "success_criteria": "Virtual patch deployed to all at-risk systems",
                    "estimated_effort": "2-4 hours"
                }
            ])

        # Generic technical remediation (applicable to all incidents)
        remediation_steps.extend([
            {
                "action": "Review and update firewall rules to block malicious IPs/domains",
                "priority": "high",
                "category": "technical",
                "owner": "Network Security",
                "timeline": "0-4h",
                "rationale": f"Block {len(context.iocs)} identified IOCs at network perimeter",
                "success_criteria": "All IOCs blocked at firewall, EDR, and web proxy",
                "estimated_effort": "2-4 hours"
            },
            {
                "action": "Deploy enhanced logging and monitoring for affected systems",
                "priority": "high",
                "category": "technical",
                "owner": "Security Operations",
                "timeline": "24-48h",
                "rationale": "Improve detection capabilities for similar attacks",
                "success_criteria": "Enhanced logging active, alerting rules deployed",
                "estimated_effort": "8-16 hours"
            },
            {
                "action": "Conduct forensic imaging of compromised systems",
                "priority": "medium",
                "category": "technical",
                "owner": "Digital Forensics",
                "timeline": "1-3 days",
                "rationale": "Preserve evidence for further investigation and legal proceedings",
                "success_criteria": "Forensic images captured and stored securely",
                "estimated_effort": "16-40 hours"
            }
        ])

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        remediation_steps.sort(key=lambda x: priority_order.get(x["priority"], 4))

        return remediation_steps

    def _generate_process_improvements(self, context: AgentContext) -> List[Dict[str, Any]]:
        """
        Generate process improvements based on incident lessons learned.

        Decision Logic:
        1. Analyze incident metrics (MTTD, MTTC, MTTR)
        2. Identify process gaps from timeline
        3. Generate specific process improvements
        4. Focus on detection, response, and communication
        """
        improvements = []
        metrics = context.incident_metadata.get("metrics", {})

        # Analyze detection time (MTTD)
        mttd_hours = metrics.get("mttd", 0) / 3600 if metrics.get("mttd") else None
        if mttd_hours and mttd_hours > 24:
            improvements.append({
                "action": "Implement enhanced threat detection rules for this attack pattern",
                "priority": "critical",
                "category": "process",
                "owner": "SOC",
                "timeline": "1-2 weeks",
                "rationale": f"MTTD was {mttd_hours:.1f} hours - unacceptably long for early threat detection",
                "success_criteria": "Similar attacks detected within 1 hour",
                "estimated_effort": "8-16 hours"
            })

        # Analyze containment time (MTTC)
        mttc_hours = metrics.get("mttc", 0) / 3600 if metrics.get("mttc") else None
        if mttc_hours and mttc_hours > 4:
            improvements.append({
                "action": "Create automated containment playbooks for common attack scenarios",
                "priority": "high",
                "category": "process",
                "owner": "Incident Response Team",
                "timeline": "2-4 weeks",
                "rationale": f"MTTC was {mttc_hours:.1f} hours - automated playbooks would reduce this significantly",
                "success_criteria": "Containment playbooks available for top 10 attack types",
                "estimated_effort": "40-80 hours"
            })

        # Generic process improvements
        improvements.extend([
            {
                "action": "Update incident response runbooks with lessons from this incident",
                "priority": "high",
                "category": "process",
                "owner": "IR Team Lead",
                "timeline": "1 week",
                "rationale": "Document specific procedures that worked well and areas for improvement",
                "success_criteria": "Updated runbooks reviewed and approved by security leadership",
                "estimated_effort": "8-16 hours"
            },
            {
                "action": "Conduct post-incident review meeting with all stakeholders",
                "priority": "high",
                "category": "process",
                "owner": "IR Team Lead",
                "timeline": "1 week",
                "rationale": "Gather feedback and identify process gaps",
                "success_criteria": "Meeting completed, action items assigned and tracked",
                "estimated_effort": "4-8 hours"
            },
            {
                "action": "Implement automated incident escalation workflows",
                "priority": "medium",
                "category": "process",
                "owner": "Security Engineering",
                "timeline": "4-6 weeks",
                "rationale": "Reduce manual overhead and improve response time",
                "success_criteria": "Automated escalation for critical/high severity incidents",
                "estimated_effort": "24-40 hours"
            },
            {
                "action": "Establish communication templates for stakeholder updates",
                "priority": "medium",
                "category": "process",
                "owner": "IR Team Lead",
                "timeline": "2 weeks",
                "rationale": "Streamline incident communication and reduce confusion",
                "success_criteria": "Templates created for executives, IT teams, and end users",
                "estimated_effort": "4-8 hours"
            }
        ])

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        improvements.sort(key=lambda x: priority_order.get(x["priority"], 4))

        return improvements

    def _generate_training_needs(self, context: AgentContext) -> List[Dict[str, Any]]:
        """Generate training needs"""
        return [
            {
                "action": "Security awareness training",
                "priority": "high",
                "category": "training",
                "audience": "All employees",
                "timeline": "quarterly"
            },
            {
                "action": "Incident response training",
                "priority": "medium",
                "category": "training",
                "audience": "IT Staf",
                "timeline": "annually"
            }
        ]

    def _create_priority_matrix(
        self,
        technical: List[Dict],
        process: List[Dict],
        training: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Create priority matrix"""
        all_actions = technical + process + training

        return {
            "critical": [a for a in all_actions if a.get("priority") == "critical"],
            "high": [a for a in all_actions if a.get("priority") == "high"],
            "medium": [a for a in all_actions if a.get("priority") == "medium"],
            "low": [a for a in all_actions if a.get("priority") == "low"]
        }

    def _determine_current_phase(self, context: AgentContext) -> IncidentPhase:
        """Determine current incident phase"""
        # Simple heuristic based on context state
        if not context.findings:
            return IncidentPhase.DETECTION
        elif not context.incident_metadata.get("root_cause"):
            return IncidentPhase.ANALYSIS
        elif not context.incident_metadata.get("contained"):
            return IncidentPhase.CONTAINMENT
        elif not context.incident_metadata.get("eradicated"):
            return IncidentPhase.ERADICATION
        elif not context.incident_metadata.get("recovered"):
            return IncidentPhase.RECOVERY
        else:
            return IncidentPhase.POST_INCIDENT

    async def _execute_phase_actions(
        self,
        context: AgentContext,
        phase: IncidentPhase
    ) -> Dict[str, Any]:
        """Execute phase-specific actions"""
        return {
            "phase": phase.value,
            "actions_completed": [],
            "next_phase": self._get_next_phase(phase).value
        }

    def _get_next_phase(self, current_phase: IncidentPhase) -> IncidentPhase:
        """Get next phase in lifecycle"""
        phase_order = [
            IncidentPhase.DETECTION,
            IncidentPhase.ANALYSIS,
            IncidentPhase.CONTAINMENT,
            IncidentPhase.ERADICATION,
            IncidentPhase.RECOVERY,
            IncidentPhase.POST_INCIDENT
        ]

        try:
            current_index = phase_order.index(current_phase)
            if current_index < len(phase_order) - 1:
                return phase_order[current_index + 1]
        except ValueError:
            pass

        return IncidentPhase.POST_INCIDENT

    async def create_jira_ticket_with_enrichment(
        self,
        incident: Any,
        analysis: Optional[AnalysisResult] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Create Jira ticket with enrichment data from Security Analyst.

        This method:
        1. Creates a Jira issue from the incident
        2. Attaches URLScan.io screenshots
        3. Adds WHOIS data as comments
        4. Adds investigation queries as comments

        Args:
            incident: Incident object
            analysis: AnalysisResult from Security Analyst Agent (optional)

        Returns:
            Dictionary with Jira issue details and attachment results
        """
        if not self.jira_manager:
            logger.warning("Jira integration not configured")
            return None

        try:
            # Create Jira issue
            jira_issue = await self.jira_manager.create_issue_from_sentyr(
                incident,
                analysis
            )

            if not jira_issue:
                logger.error("Failed to create Jira issue")
                return None

            result = {
                "jira_key": jira_issue.key,
                "jira_id": jira_issue.id,
                "jira_url": f"{self.jira_manager.api_client.base_url}/browse/{jira_issue.key}",
                "enrichment_attached": False
            }

            # Attach enrichment data if available
            if analysis:
                enrichment_results = await self.jira_manager.attach_enrichment_data(
                    jira_issue.key,
                    analysis
                )
                result["enrichment_attached"] = any(enrichment_results.values())
                result["enrichment_details"] = enrichment_results

                logger.info(
                    f"Created Jira ticket {jira_issue.key} with enrichment: "
                    f"URLScan={enrichment_results.get('urlscan_screenshots', False)}, "
                    f"WHOIS={enrichment_results.get('whois_comment', False)}, "
                    f"Queries={enrichment_results.get('investigation_queries_comment', False)}"
                )
            else:
                logger.info(f"Created Jira ticket {jira_issue.key} without enrichment data")

            return result

        except Exception as e:
            logger.error(f"Error creating Jira ticket with enrichment: {e}")
            return None
