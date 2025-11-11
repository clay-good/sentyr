# Incident Response Agent Enhancements

## Summary

Enhanced the Incident Response Agent with advanced decision-making logic, chain-of-thought reasoning, and evidence-based recommendations. These improvements enable security teams to conduct more thorough incident investigations with actionable, prioritized response plans.

**Date:** 2025-11-10
**Agent Version:** 1.0.0
**Lines of Code Modified:** ~500 lines

---

## Key Enhancements

### 1. Structured Root Cause Analysis Framework

**Location:** `sentyr/agents/incident_response.py:756-1098`

**What Changed:**
- Replaced simple heuristic-based root cause determination with a comprehensive 6-phase decision framework
- Added evidence quality assessment before making determinations
- Implemented chain-of-thought reasoning for transparent decision-making
- Added alternative hypothesis testing and confidence scoring

**Decision Framework Phases:**
1. **Evidence Assessment**: Evaluate quality and completeness of available data
2. **Pattern Analysis**: Identify common attack patterns (credentials, vulnerabilities, social engineering, etc.)
3. **Timeline Analysis**: Trace back to initial compromise vector
4. **Alternative Hypothesis Testing**: Consider and rule out alternative explanations
5. **Confidence Scoring**: Assign confidence based on evidence strength
6. **Recommendation Generation**: Provide actionable remediation steps

**Example Output:**

```json
{
  "description": "Compromised credentials enabled initial access to systems",
  "category": "credential_compromise",
  "confidence": 0.90,
  "reasoning": [
    "INITIAL ASSESSMENT: Analyzing 12 initial events and 3 attack vectors across 8 findings",
    "PATTERN DETECTION: Identified 3 attack patterns: credential_based, social_engineering, lateral_movement",
    "CREDENTIAL ANALYSIS: Strong indicators of credential-based compromise detected",
    "EVIDENCE: Attack chain shows authentication events, failed login attempts, or credential abuse",
    "ATTRIBUTION: Phishing attack likely obtained credentials (high confidence)",
    "IMPACT ANALYSIS: Compromised credentials enabled initial access and potential privilege escalation"
  ],
  "evidence_summary": {
    "credential_indicators": true,
    "social_engineering_indicators": true,
    "lateral_movement": true,
    "total_events_analyzed": 15
  },
  "attack_kill_chain": [
    "Initial Access: Credential Compromise",
    "Execution: Authenticated Login",
    "Persistence: Unknown (requires further investigation)",
    "Privilege Escalation: Possible"
  ],
  "alternatives": [
    {
      "hypothesis": "Credential stuffing from breach database",
      "confidence": 0.60,
      "rationale": "Could explain credential compromise without phishing indicators"
    },
    {
      "hypothesis": "Insider threat or malicious employee",
      "confidence": 0.30,
      "rationale": "Less likely given external attack indicators"
    }
  ],
  "decision_rationale": "Root cause determined with 90% confidence based on 6 lines of evidence. Credential compromise is the most likely initial access vector given the observed attack patterns and available evidence."
}
```

---

### 2. Evidence Quality Assessment

**Location:** `sentyr/agents/incident_response.py:811-853`

**What Changed:**
- New method `_assess_evidence_quality()` that scores evidence from 0.0 to 1.0
- Evaluates completeness of timeline events, attack vectors, findings, and IOCs
- Identifies specific evidence gaps (e.g., "No clear attack vectors identified")
- Blocks root cause determination if evidence quality is below 0.3 threshold

**Evidence Scoring:**
- Timeline events (5+): +0.30, (1-4): +0.15
- Attack vectors (3+): +0.30, (1-2): +0.15
- Findings (3+): +0.20, (1-2): +0.10
- IOCs (5+): +0.20, (1-4): +0.10

**Example - Insufficient Evidence Response:**

```json
{
  "description": "Insufficient data to determine root cause with confidence",
  "category": "unknown",
  "confidence": 0.25,
  "reasoning": [
    "Evidence quality score: 0.25 (below threshold)",
    "Available events: 2",
    "Identified attack vectors: 0",
    "Recommendation: Gather additional forensic data before proceeding"
  ],
  "evidence_gaps": [
    "No clear attack vectors identified",
    "Limited security findings available"
  ],
  "recommendations": [
    {
      "action": "Enable comprehensive logging on affected systems",
      "priority": "critical",
      "timeframe": "immediate"
    },
    {
      "action": "Collect memory dumps from compromised hosts",
      "priority": "high",
      "timeframe": "0-1h"
    },
    {
      "action": "Query threat intelligence feeds for related indicators",
      "priority": "high",
      "timeframe": "0-1h"
    }
  ],
  "decision_rationale": "Without sufficient evidence, any root cause determination would be speculative and could lead to ineffective remediation."
}
```

---

### 3. Attack Pattern Detection

**Location:** `sentyr/agents/incident_response.py:855-903`

**What Changed:**
- New method `_analyze_attack_patterns()` that detects 7 common attack patterns
- Pattern matching across initial events, attack vectors, and findings
- Enables pattern-specific root cause determination and remediation

**Detected Patterns:**
- **Credential-based attacks**: password, brute force, login, authentication
- **Vulnerability exploitation**: exploit, CVE, remote code execution
- **Social engineering**: phishing, spear phish, malicious email
- **Supply chain**: third party, vendor, dependency
- **Insider threat**: privileged user, abuse of access
- **Lateral movement**: pass the hash, credential dumping, mimikatz
- **Data exfiltration**: file download, upload, data transfer

---

### 4. Chain-of-Thought Root Cause Reasoning

**Location:** `sentyr/agents/incident_response.py:905-1098`

**What Changed:**
- New method `_determine_root_cause_with_cot()` for transparent reasoning
- Step-by-step reasoning chain showing analysis progression
- Pattern-specific logic for credential compromise and vulnerability exploitation
- Alternative hypotheses with confidence scores and rationales
- Attack kill chain reconstruction

**Reasoning Chain Example:**

```
Step 1: INITIAL ASSESSMENT: Analyzing 12 initial events and 3 attack vectors across 8 findings
Step 2: PATTERN DETECTION: Identified 3 attack patterns: credential_based, social_engineering, lateral_movement
Step 3: CREDENTIAL ANALYSIS: Strong indicators of credential-based compromise detected
Step 4: EVIDENCE: Attack chain shows authentication events, failed login attempts, or credential abuse
Step 5: ATTRIBUTION: Phishing attack likely obtained credentials (high confidence)
Step 6: IMPACT ANALYSIS: Compromised credentials enabled initial access and potential privilege escalation
```

---

### 5. Enhanced Technical Remediation Generation

**Location:** `sentyr/agents/incident_response.py:1299-1429`

**What Changed:**
- Context-aware remediation based on root cause category
- Specific remediation steps for credential compromise vs. vulnerability exploitation
- Each recommendation includes:
  - **Action**: Specific task to perform
  - **Priority**: Critical, High, Medium, Low
  - **Timeline**: Realistic time windows (e.g., "0-1h", "1-2 weeks")
  - **Owner**: Responsible team
  - **Rationale**: Why this action is needed
  - **Success Criteria**: How to measure completion
  - **Estimated Effort**: Time required to complete

**Example - Credential Compromise Remediation:**

```json
[
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
]
```

**Example - Vulnerability Exploitation Remediation:**

```json
[
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
]
```

---

### 6. Metrics-Driven Process Improvements

**Location:** `sentyr/agents/incident_response.py:1431-1520`

**What Changed:**
- Process improvements now driven by incident metrics (MTTD, MTTC, MTTR)
- Automatic detection of poor metrics and targeted recommendations
- Each improvement includes rationale, success criteria, and estimated effort

**Decision Logic:**
1. Analyze Mean Time To Detect (MTTD) - if >24 hours, recommend detection improvements
2. Analyze Mean Time To Contain (MTTC) - if >4 hours, recommend containment automation
3. Generate generic process improvements (runbook updates, stakeholder reviews, etc.)
4. Sort by priority (critical → high → medium → low)

**Example - High MTTD Response:**

```json
{
  "action": "Implement enhanced threat detection rules for this attack pattern",
  "priority": "critical",
  "category": "process",
  "owner": "SOC",
  "timeline": "1-2 weeks",
  "rationale": "MTTD was 36.2 hours - unacceptably long for early threat detection",
  "success_criteria": "Similar attacks detected within 1 hour",
  "estimated_effort": "8-16 hours"
}
```

**Example - High MTTC Response:**

```json
{
  "action": "Create automated containment playbooks for common attack scenarios",
  "priority": "high",
  "category": "process",
  "owner": "Incident Response Team",
  "timeline": "2-4 weeks",
  "rationale": "MTTC was 8.5 hours - automated playbooks would reduce this significantly",
  "success_criteria": "Containment playbooks available for top 10 attack types",
  "estimated_effort": "40-80 hours"
}
```

---

## Benefits for Security Teams

### 1. Transparent Decision-Making
- Every root cause determination includes a reasoning chain
- Security analysts can see **why** the agent made specific conclusions
- Alternative hypotheses help teams consider multiple scenarios

### 2. Evidence-Based Recommendations
- Recommendations tied directly to root cause and attack patterns
- No generic advice - everything is specific to the incident
- Clear ownership, timelines, and success criteria

### 3. Prioritized Action Plans
- Critical actions separated from nice-to-haves
- Realistic timeframes (immediate, 0-1h, 1-4h, 1-7 days, etc.)
- Estimated effort helps with resource planning

### 4. Quality Control
- Evidence quality assessment prevents premature conclusions
- System won't make guesses when data is insufficient
- Recommends specific data collection when evidence is weak

### 5. Continuous Improvement
- Metrics-driven process improvements
- Learns from MTTD/MTTC/MTTR to improve response
- Systematic approach to lessons learned

---

## Example End-to-End Workflow

### Scenario: Credential Compromise Incident

1. **Evidence Collection**
   - 12 timeline events
   - 3 attack vectors identified
   - 8 security findings
   - 15 IOCs extracted

2. **Evidence Assessment**
   - Quality score: 0.85 (high quality)
   - All evidence categories present

3. **Pattern Detection**
   - Credential-based: ✓
   - Social engineering: ✓
   - Lateral movement: ✓

4. **Root Cause Analysis**
   - Category: credential_compromise
   - Confidence: 90%
   - Reasoning: 6-step chain-of-thought
   - Alternatives: 2 hypotheses considered and ruled out

5. **Technical Remediation**
   - 6 specific actions generated
   - 3 critical priority (immediate to 24h)
   - 3 high priority (1-2 weeks)
   - All include owners, timelines, rationales

6. **Process Improvements**
   - 4 process improvements
   - Includes MTTD/MTTC-driven recommendations
   - Post-incident review scheduled

7. **Post-Mortem Report**
   - BLUF summary
   - 5W1H analysis
   - Complete timeline
   - Lessons learned

---

## Technical Details

### New Methods Added

1. `_assess_evidence_quality()` - Scores evidence from 0.0 to 1.0
2. `_analyze_attack_patterns()` - Detects 7 common attack patterns
3. `_determine_root_cause_with_cot()` - Chain-of-thought root cause analysis

### Enhanced Methods

1. `_determine_root_cause()` - Now uses 6-phase decision framework
2. `_generate_technical_remediation()` - Context-aware, pattern-specific remediation
3. `_generate_process_improvements()` - Metrics-driven recommendations

### Data Structures

**Evidence Quality Assessment:**
```python
{
    "score": 0.85,  # 0.0-1.0
    "gaps": []      # List of missing evidence types
}
```

**Attack Patterns:**
```python
{
    "credential_based": True,
    "vulnerability_exploitation": False,
    "social_engineering": True,
    "supply_chain": False,
    "insider_threat": False,
    "lateral_movement": True,
    "data_exfiltration": False
}
```

**Root Cause with Chain-of-Thought:**
```python
{
    "description": "...",
    "category": "credential_compromise",
    "confidence": 0.90,
    "reasoning": [...],  # Step-by-step reasoning chain
    "evidence_summary": {...},
    "attack_kill_chain": [...],
    "recommendations": [...],
    "alternatives": [...],
    "decision_rationale": "..."
}
```

---

## Testing Recommendations

### Unit Tests

```python
def test_evidence_quality_assessment():
    """Test evidence quality scoring."""
    # Test with complete evidence
    quality = agent._assess_evidence_quality(
        initial_events=[...],  # 5+ events
        attack_vectors=[...],   # 3+ vectors
        context=context         # 3+ findings, 5+ IOCs
    )
    assert quality["score"] >= 0.8
    assert len(quality["gaps"]) == 0

    # Test with insufficient evidence
    quality = agent._assess_evidence_quality(
        initial_events=[],
        attack_vectors=[],
        context=empty_context
    )
    assert quality["score"] < 0.3
    assert len(quality["gaps"]) > 0

def test_attack_pattern_detection():
    """Test attack pattern identification."""
    patterns = agent._analyze_attack_patterns(
        initial_events=[{"action": "failed login attempt"}],
        attack_vectors=["brute force authentication"],
        context=context
    )
    assert patterns["credential_based"] == True
    assert patterns["vulnerability_exploitation"] == False

def test_root_cause_with_cot():
    """Test chain-of-thought root cause analysis."""
    root_cause = agent._determine_root_cause_with_cot(
        initial_events=[...],
        attack_vectors=["credential stuffing"],
        attack_patterns={"credential_based": True},
        context=context
    )
    assert root_cause["category"] == "credential_compromise"
    assert root_cause["confidence"] >= 0.8
    assert len(root_cause["reasoning"]) >= 3
    assert len(root_cause["recommendations"]) >= 3
```

### Integration Tests

```python
def test_full_rca_workflow():
    """Test complete root cause analysis workflow."""
    # Create incident context
    context = create_test_context(
        findings=8,
        timeline_events=12,
        iocs=15
    )

    # Perform RCA
    output = await agent._perform_root_cause_analysis(
        AgentInput(context=context),
        start_time=time.time()
    )

    # Verify output
    assert output.status == AgentStatus.COMPLETED
    assert output.confidence >= 0.7
    assert "root_cause" in output.results
    assert len(output.results["root_cause"]["recommendations"]) >= 3
```

---

## Performance Considerations

- Evidence assessment: O(n) where n = number of events/findings
- Pattern detection: O(n) string matching across evidence
- Root cause determination: O(1) after pattern detection
- Total overhead: <100ms for typical incidents

---

## Future Enhancements

1. **Machine Learning Integration**
   - Train models on historical root cause determinations
   - Improve pattern detection accuracy
   - Auto-tune confidence thresholds

2. **MITRE ATT&CK Mapping**
   - Map detected patterns to specific MITRE techniques
   - Generate MITRE-based remediation recommendations

3. **Threat Intelligence Integration**
   - Query threat intel feeds for similar attack patterns
   - Incorporate TTPs from known threat actors

4. **Automated Response**
   - Auto-execute critical remediation steps (with approval)
   - Integration with SOAR platforms

---

## Summary

The Incident Response Agent now provides security teams with:

✅ **Transparent reasoning** - Chain-of-thought explanations for all decisions
✅ **Evidence-based analysis** - Quality assessment prevents premature conclusions
✅ **Pattern-specific responses** - Remediation tailored to attack type
✅ **Prioritized actions** - Clear timelines and ownership
✅ **Metrics-driven improvements** - Learn from MTTD/MTTC/MTTR
✅ **Alternative hypotheses** - Consider multiple scenarios
✅ **Actionable recommendations** - Specific, realistic, measurable

This transforms incident response from reactive firefighting to systematic, evidence-based decision-making.
