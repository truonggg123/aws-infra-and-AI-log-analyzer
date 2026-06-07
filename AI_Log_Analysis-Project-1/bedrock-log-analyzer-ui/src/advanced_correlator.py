"""
Advanced Multi-Log Correlator - Senior-Level Implementation
Addresses critical issues:
1. Rich correlation keys (trace_id, request_id, session_id, instance_id)
2. Timeline sequence detection with ordering
3. Rule engine (config-driven, not hardcoded)
4. AI-powered recommendations (Bedrock integration)
5. Advanced confidence scoring (severity + sequence + anomaly)
6. Context + Timeline + Intent correlation (not just IP matching)
"""
import re
import json
import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from models import LogEntry, AnalysisData


# ============================================================
# Enhanced Data Models
# ============================================================

@dataclass
class RichCorrelationKey:
    """
    Rich correlation keys - NOT just IP addresses!
    Handles NAT, proxies, and internal traffic properly.
    """
    # Primary keys (strongest correlation)
    trace_ids: Set[str] = field(default_factory=set)        # X-Trace-Id, X-Request-Id
    request_ids: Set[str] = field(default_factory=set)      # Request correlation
    session_ids: Set[str] = field(default_factory=set)      # User session
    
    # Secondary keys (weaker but useful)
    ip_addresses: Set[str] = field(default_factory=set)     # Can be NAT'd
    user_arns: Set[str] = field(default_factory=set)        # IAM users
    instance_ids: Set[str] = field(default_factory=set)     # EC2 instances
    
    # Contextual keys
    user_agents: Set[str] = field(default_factory=set)      # Browser fingerprint
    api_actions: Set[str] = field(default_factory=set)      # AWS API calls
    
    # Temporal context
    timestamps: List[datetime] = field(default_factory=list)


@dataclass
class TimelineEvent:
    """Single event in a timeline with precise ordering"""
    timestamp: datetime
    source: str                    # "vpc_flow", "cloudtrail", "application"
    event_type: str                # "network_reject", "api_deny", "sql_injection"
    severity: str                  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    actor: str                     # IP, user, or trace_id
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSequence:
    """Detected attack sequence with ordering"""
    sequence_id: str
    pattern_name: str              # "reconnaissance_to_exploit", "privilege_escalation"
    events: List[TimelineEvent]    # Ordered by time
    confidence: float              # 0-100
    
    # Sequence analysis
    total_duration_seconds: float
    average_delay_seconds: float   # Delay between steps
    is_automated: bool             # Fast sequence = bot
    
    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class AdvancedCorrelatedEvent:
    """Enhanced correlated event with rich context"""
    correlation_id: str
    primary_correlation_key: str   # trace_id > request_id > session_id > IP
    correlation_strength: str      # "STRONG", "MEDIUM", "WEAK"
    
    # Timeline (ordered events)
    timeline: List[TimelineEvent]
    attack_sequences: List[AttackSequence]
    
    # Classification
    event_type: str
    severity: str
    confidence_score: float        # Advanced scoring
    
    # Context analysis
    intent: str                    # "data_exfiltration", "privilege_escalation", "dos"
    context: Dict[str, Any]        # Rich contextual data
    
    # AI-generated insights
    ai_summary: str = ""
    ai_recommendations: List[str] = field(default_factory=list)
    
    # Evidence
    evidence_by_source: Dict[str, List[Dict]] = field(default_factory=dict)
    
    # ---- Convenience properties for UI compatibility ----
    
    @property
    def attack_name(self) -> str:
        """Human-readable attack name from best matching rule or event type"""
        if self.attack_sequences:
            return self.attack_sequences[0].pattern_name
        # Fallback: make event_type human readable
        return self.event_type.replace('_', ' ').title()
    
    @property
    def sources(self) -> List[str]:
        """List of log sources involved in this correlated event"""
        return self.context.get('sources_involved', list(self.evidence_by_source.keys()))
    
    @property
    def ai_recommendation(self) -> str:
        """Combined AI recommendation text"""
        if self.ai_recommendations:
            return '\n'.join(self.ai_recommendations)
        return self.ai_summary or "No AI recommendation available yet — run AI enhancement for detailed analysis."
    
    @property
    def evidence(self) -> List[str]:
        """Flattened evidence list across all sources"""
        result = []
        for source, events in self.evidence_by_source.items():
            for event in events:
                result.append(f"[{source}] {event.get('timestamp', '')} - {event.get('message', '')}")
        return result
    
    @property
    def matched_rules(self) -> List[str]:
        """List of matched detection rule names"""
        rules = []
        for seq in self.attack_sequences:
            rules.append(f"{seq.pattern_name} (Confidence: {seq.confidence:.1f}%)")
        return rules
    
    @property
    def correlation_keys(self) -> Dict[str, str]:
        """Correlation keys as a dict for UI rendering"""
        key_type = 'unknown'
        key_value = self.primary_correlation_key
        if ':' in self.primary_correlation_key:
            key_type, key_value = self.primary_correlation_key.split(':', 1)
        return {
            key_type: key_value,
            'strength': self.correlation_strength,
            'correlation_id': self.correlation_id
        }


# ============================================================
# Rule Engine (Config-Driven)
# ============================================================

@dataclass
class CorrelationRule:
    """Config-driven correlation rule"""
    rule_id: str
    name: str
    description: str
    
    # Pattern matching
    required_sources: List[str]    # ["vpc_flow", "application"]
    event_sequence: List[str]      # ["network_reject", "sql_injection"]
    max_time_gap_seconds: int      # Max delay between events
    
    # Classification
    event_type: str
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    
    # Scoring
    base_confidence: float
    confidence_modifiers: Dict[str, float]  # {"has_trace_id": +20, "automated": +10}
    
    # Thresholds (optional, for DoS/brute force detection)
    minimum_event_count: Optional[int] = None  # Minimum events to trigger rule
    minimum_unique_ips: Optional[int] = None   # Minimum unique IPs for distributed attacks


class RuleEngine:
    """Load and evaluate correlation rules from config"""
    
    def __init__(self, rules_config_path: Optional[str] = None):
        self.rules: List[CorrelationRule] = []
        if rules_config_path:
            self.load_rules(rules_config_path)
        else:
            self.load_default_rules()
    
    def load_default_rules(self):
        """Load default correlation rules"""
        self.rules = [
            # Rule 1: Reconnaissance to Exploit
            CorrelationRule(
                rule_id="R001",
                name="Reconnaissance to Exploit",
                description="Network scanning followed by application attack",
                required_sources=["vpc_flow", "application"],
                event_sequence=["network_reject", "sql_injection"],
                max_time_gap_seconds=300,  # 5 minutes
                event_type="coordinated_attack",
                severity="CRITICAL",
                mitre_tactics=["TA0001", "TA0002"],  # Initial Access, Execution
                mitre_techniques=["T1190", "T1059"],
                base_confidence=70.0,
                confidence_modifiers={
                    "has_trace_id": 20.0,
                    "automated": 10.0,
                    "multiple_targets": 15.0
                }
            ),
            
            # Rule 2: Privilege Escalation
            CorrelationRule(
                rule_id="R002",
                name="Privilege Escalation Attempt",
                description="API access denied followed by repeated attempts",
                required_sources=["cloudtrail", "application"],
                event_sequence=["api_deny", "unauthorized_access"],
                max_time_gap_seconds=600,  # 10 minutes
                event_type="privilege_escalation",
                severity="HIGH",
                mitre_tactics=["TA0004"],  # Privilege Escalation
                mitre_techniques=["T1078"],
                base_confidence=65.0,
                confidence_modifiers={
                    "has_user_arn": 25.0,
                    "repeated_attempts": 15.0
                }
            ),
            
            # Rule 3: Data Exfiltration
            CorrelationRule(
                rule_id="R003",
                name="Data Exfiltration Pattern",
                description="Database query spike + network traffic spike",
                required_sources=["database", "vpc_flow"],
                event_sequence=["slow_query", "high_traffic"],
                max_time_gap_seconds=120,  # 2 minutes
                event_type="data_exfiltration",
                severity="CRITICAL",
                mitre_tactics=["TA0010"],  # Exfiltration
                mitre_techniques=["T1041"],
                base_confidence=75.0,
                confidence_modifiers={
                    "large_data_volume": 20.0,
                    "external_ip": 15.0
                }
            ),
            
            # Rule 4: Application-Database Issue
            CorrelationRule(
                rule_id="R004",
                name="Application-Database Connection Issue",
                description="App connection timeouts + DB connection errors",
                required_sources=["application", "database"],
                event_sequence=["connection_timeout", "too_many_connections"],
                max_time_gap_seconds=60,  # 1 minute
                event_type="performance_issue",
                severity="HIGH",
                mitre_tactics=[],
                mitre_techniques=[],
                base_confidence=80.0,
                confidence_modifiers={
                    "has_instance_id": 15.0,
                    "high_frequency": 10.0
                }
            )
        ]
    
    def load_rules(self, config_path: str):
        """Load rules from JSON config file"""
        try:
            with open(config_path, 'r') as f:
                rules_data = json.load(f)
                for rule_data in rules_data.get('rules', []):
                    rule = CorrelationRule(**rule_data)
                    self.rules.append(rule)
        except Exception as e:
            print(f"Failed to load rules from {config_path}: {e}")
            self.load_default_rules()
    
    def evaluate(self, timeline: List[TimelineEvent]) -> List[Tuple[CorrelationRule, float]]:
        """Evaluate timeline against all rules, return matching rules with confidence"""
        matches = []
        
        for rule in self.rules:
            confidence = self._evaluate_rule(rule, timeline)
            if confidence > 0:
                matches.append((rule, confidence))

        matches = self._prioritize_contextual_matches(timeline, matches)
        return sorted(matches, key=lambda x: x[1], reverse=True)

    def _prioritize_contextual_matches(
        self,
        timeline: List[TimelineEvent],
        matches: List[Tuple[CorrelationRule, float]]
    ) -> List[Tuple[CorrelationRule, float]]:
        """
        Prefer the most specific web/network signal over weak cross-source IP matches.
        This prevents deployment/admin CloudTrail noise from masking obvious fuzzing,
        HTTP flood, brute force, or scanning activity in the UI.
        """
        if not matches:
            return matches

        event_types = [event.event_type for event in timeline]
        boosted = []
        for rule, confidence in matches:
            adjusted = confidence
            if "web_fuzzing" in event_types and rule.event_type == "web_fuzzing":
                adjusted += 30.0
            elif "http_error" in event_types and rule.event_type == "application_dos":
                adjusted += 15.0
            elif "network_reject" in event_types and rule.event_type in {"port_scan", "denial_of_service"}:
                adjusted += 10.0

            # A lone CloudTrail + VPC IP match is weak during deploy/demo traffic.
            if rule.event_type == "lateral_movement":
                sources = set(event.source for event in timeline)
                has_specific_attack_signal = any(
                    et in event_types
                    for et in ("web_fuzzing", "sql_injection", "path_traversal", "xss", "brute_force", "port_scan")
                )
                if has_specific_attack_signal:
                    adjusted -= 40.0
                elif sources == {"cloudtrail", "vpc_flow"}:
                    adjusted -= 20.0

            boosted.append((rule, max(0.0, min(adjusted, 100.0))))

        return boosted
    
    def _evaluate_rule(self, rule: CorrelationRule, timeline: List[TimelineEvent]) -> float:
        """Evaluate single rule against timeline"""
        # Check if required sources are present
        sources_present = set(event.source for event in timeline)
        
        if not all(src in sources_present for src in rule.required_sources):
            return 0.0
        
        # CRITICAL: Check minimum event count threshold (for DoS detection)
        min_event_count = getattr(rule, 'minimum_event_count', None)
        if min_event_count and len(timeline) < min_event_count:
            if rule.rule_id == 'R007':
                print(f"[DoS Filter] Rejected: Only {len(timeline)} events, need {min_event_count} minimum")
            return 0.0
        
        # CRITICAL: Check minimum unique IPs (for DoS detection)
        min_unique_ips = getattr(rule, 'minimum_unique_ips', None)
        if min_unique_ips:
            unique_actors = len(set(event.actor for event in timeline))
            if unique_actors < min_unique_ips:
                if rule.rule_id == 'R007':
                    print(f"[DoS Filter] Rejected: Only {unique_actors} unique IPs, need {min_unique_ips} minimum")
                return 0.0
        
        # Check if event sequence matches
        sequence_match = self._check_sequence(rule.event_sequence, timeline, rule.max_time_gap_seconds)
        if not sequence_match:
            return 0.0
        
        # Calculate confidence with modifiers
        confidence = rule.base_confidence
        
        # Apply modifiers based on timeline characteristics
        if any(event.metadata.get('trace_id') for event in timeline):
            confidence += rule.confidence_modifiers.get('has_trace_id', 0)
        
        if self._is_automated(timeline):
            confidence += rule.confidence_modifiers.get('automated', 0)
        
        # Apply high_frequency modifier based on actual event count
        if len(timeline) >= 100:
            confidence += rule.confidence_modifiers.get('high_frequency', 0)
        
        # Apply multiple_sources modifier
        if len(sources_present) > 1:
            confidence += rule.confidence_modifiers.get('multiple_sources', 0)
        
        return min(confidence, 100.0)
    
    def _check_sequence(self, expected_sequence: List[str], timeline: List[TimelineEvent], max_gap: int) -> bool:
        """Check if expected sequence appears in timeline with time constraints"""
        if not expected_sequence:
            return True
        
        # Find first event of sequence
        seq_idx = 0
        for i, event in enumerate(timeline):
            if event.event_type == expected_sequence[seq_idx]:
                seq_idx += 1
                if seq_idx >= len(expected_sequence):
                    return True
                
                # Check time gap to next event
                if i + 1 < len(timeline):
                    time_gap = (timeline[i + 1].timestamp - event.timestamp).total_seconds()
                    if time_gap > max_gap:
                        seq_idx = 0  # Reset if gap too large

        return seq_idx >= len(expected_sequence)
    
    def _is_automated(self, timeline: List[TimelineEvent]) -> bool:
        """Detect if timeline shows automated behavior (bot)"""
        if len(timeline) < 3:
            return False
        
        # Calculate average delay between events
        delays = []
        for i in range(len(timeline) - 1):
            delay = (timeline[i + 1].timestamp - timeline[i].timestamp).total_seconds()
            delays.append(delay)
        
        avg_delay = sum(delays) / len(delays)
        
        # Automated if average delay < 5 seconds
        return avg_delay < 5.0


# ============================================================
# Advanced Correlator
# ============================================================

class AdvancedCorrelator:
    """
    Senior-level multi-log correlator with:
    - Rich correlation keys (trace_id, request_id, session_id)
    - Timeline sequence detection
    - Rule engine (config-driven)
    - Advanced confidence scoring
    - Context + Timeline + Intent analysis
    """
    
    def __init__(self, rules_config_path: Optional[str] = None):
        self.rule_engine = RuleEngine(rules_config_path)
        
        # Regex patterns for extraction
        self.trace_id_pattern = re.compile(r'(?:trace[-_]?id|x-trace-id|x-request-id)[:\s=]+([a-f0-9-]{20,})', re.IGNORECASE)
        self.request_id_pattern = re.compile(r'(?:request[-_]?id)[:\s=]+([a-f0-9-]{10,})', re.IGNORECASE)
        self.session_id_pattern = re.compile(r'(?:session[-_]?id|jsessionid)[:\s=]+([a-zA-Z0-9]{10,})', re.IGNORECASE)
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.instance_pattern = re.compile(r'\b(i-[a-f0-9]{8,17})\b')
        self.arn_pattern = re.compile(r'arn:aws:[^:]+:[^:]*:[^:]*:[^/]+/[^\s"]+')
    
    def correlate_advanced(
        self,
        log_sources: Dict[str, Tuple[List[LogEntry], AnalysisData]]
    ) -> List[AdvancedCorrelatedEvent]:
        """
        Advanced correlation with rich keys and timeline analysis.
        
        Args:
            log_sources: Dict mapping log_group_name → (entries, analysis)
        
        Returns:
            List of AdvancedCorrelatedEvent with rich context
        """
        # Step 1: Extract rich correlation keys
        rich_keys = self._extract_rich_keys(log_sources)
        
        # Step 2: Build timeline for each correlation key
        timelines = self._build_timelines(log_sources, rich_keys)
        
        # Step 3: Detect attack sequences using rule engine
        correlated_events = []
        for correlation_key, timeline in timelines.items():
            event = self._analyze_timeline(correlation_key, timeline)
            if event:
                correlated_events.append(event)
        
        return correlated_events
    
    def correlate_multi_source(
        self,
        log_entries: List[LogEntry],
        clustered_patterns: Optional[List] = None,
        time_window_seconds: int = 3600
    ) -> List[AdvancedCorrelatedEvent]:
        """
        Multi-source correlation with optional pattern clustering.
        
        Args:
            log_entries: List of parsed log entries from multiple sources
            clustered_patterns: Pre-clustered patterns (optional, for noise reduction)
            time_window_seconds: Time window for correlation (default: 1 hour)
        
        Returns:
            List of AdvancedCorrelatedEvent
        """
        # If patterns provided, filter log entries to significant ones
        filtered_entries = log_entries
        
        # Use all entries for correlation to catch low-frequency targeted attacks
        filtered_entries = log_entries
        
        # Group entries by source for correlation
        entries_by_source = {}
        for entry in filtered_entries:
            source = entry.component or "unknown"
            if source not in entries_by_source:
                entries_by_source[source] = []
            entries_by_source[source].append(entry)
        
        # Build log_sources format for correlate_advanced
        from models import AnalysisData
        log_sources = {}
        
        for source, entries in entries_by_source.items():
            # Create minimal AnalysisData
            analysis = AnalysisData(
                total_entries=len(entries),
                error_patterns=[],
                severity_distribution={},
                components={}
            )
            log_sources[source] = (entries, analysis)
        
        # Use existing correlate_advanced logic
        return self.correlate_advanced(log_sources)
    
    # ---- Internal Methods ----
    
    def _extract_rich_keys(
        self,
        log_sources: Dict[str, Tuple[List[LogEntry], AnalysisData]]
    ) -> Dict[str, RichCorrelationKey]:
        """Extract rich correlation keys from all sources"""
        keys_by_source = {}
        
        for log_group, (entries, analysis) in log_sources.items():
            key = RichCorrelationKey()
            
            for entry in entries:
                text = (entry.content or '') + ' ' + (entry.message or '')
                
                # Extract trace IDs (HIGHEST PRIORITY)
                trace_ids = self.trace_id_pattern.findall(text)
                key.trace_ids.update(trace_ids)
                
                # Extract request IDs
                request_ids = self.request_id_pattern.findall(text)
                key.request_ids.update(request_ids)
                
                # Extract session IDs
                session_ids = self.session_id_pattern.findall(text)
                key.session_ids.update(session_ids)
                
                # Extract IPs (lower priority due to NAT)
                ips = self.ip_pattern.findall(text)
                # Filter out private IPs for external correlation
                public_ips = [ip for ip in ips if not self._is_private_ip(ip)]
                key.ip_addresses.update(public_ips)
                
                # Extract instance IDs
                instances = self.instance_pattern.findall(text)
                key.instance_ids.update(instances)
                
                # Extract ARNs (CloudTrail)
                if 'cloudtrail' in log_group.lower():
                    arns = self.arn_pattern.findall(text)
                    key.user_arns.update(arns)
                
                # Parse timestamp
                if entry.timestamp:
                    try:
                        ts = self._parse_timestamp(entry.timestamp)
                        if ts:
                            key.timestamps.append(ts)
                    except:
                        pass
            
            keys_by_source[log_group] = key
        
        return keys_by_source
    
    def _build_timelines(
        self,
        log_sources: Dict[str, Tuple[List[LogEntry], AnalysisData]],
        rich_keys: Dict[str, RichCorrelationKey]
    ) -> Dict[str, List[TimelineEvent]]:
        """
        Build timelines grouped by correlation key.
        Priority: trace_id > request_id > session_id > instance_id > IP
        """
        timelines = defaultdict(list)
        
        # Find all unique correlation keys across sources
        all_trace_ids = set()
        all_request_ids = set()
        all_session_ids = set()
        all_instance_ids = set()
        all_ips = set()
        
        for key in rich_keys.values():
            all_trace_ids.update(key.trace_ids)
            all_request_ids.update(key.request_ids)
            all_session_ids.update(key.session_ids)
            all_instance_ids.update(key.instance_ids)
            all_ips.update(key.ip_addresses)
        
        # Build timeline for each correlation key
        for log_group, (entries, analysis) in log_sources.items():
            source_type = self._get_source_type(log_group)
            
            for entry in entries:
                text = (entry.content or '') + ' ' + (entry.message or '')
                
                # Determine ALL correlation keys this event belongs to
                matched_keys = []
                
                # Check trace_id (STRONGEST)
                for trace_id in all_trace_ids:
                    if trace_id in text:
                        matched_keys.append((f"trace:{trace_id}", "STRONG"))
                
                # Check request_id
                for request_id in all_request_ids:
                    if request_id in text:
                        matched_keys.append((f"request:{request_id}", "MEDIUM"))
                
                # Check session_id
                for session_id in all_session_ids:
                    if session_id in text:
                        matched_keys.append((f"session:{session_id}", "MEDIUM"))
                
                # Check instance_id
                for instance_id in all_instance_ids:
                    if instance_id in text:
                        matched_keys.append((f"instance:{instance_id}", "MEDIUM"))
                
                # Check IP (WEAKEST)
                for ip in all_ips:
                    if ip in text:
                        matched_keys.append((f"ip:{ip}", "WEAK"))
                
                if not matched_keys:
                    continue
                
                # Create timeline event
                ts = self._parse_timestamp(entry.timestamp)
                if not ts:
                    continue
                
                # Add event to ALL matched timelines
                for correlation_key, correlation_strength in matched_keys:
                    event = TimelineEvent(
                        timestamp=ts,
                        source=source_type,
                        event_type=self._classify_event_type(entry, source_type),
                        severity=entry.severity or "UNKNOWN",
                        actor=correlation_key.split(':')[1],
                        message=entry.message or entry.content[:200],
                        metadata={
                            'correlation_key': correlation_key,
                            'correlation_strength': correlation_strength,
                            'component': entry.component,
                            'log_group': log_group
                        }
                    )
                    
                    timelines[correlation_key].append(event)
        
        # Sort each timeline by timestamp
        for key in timelines:
            timelines[key].sort(key=lambda e: e.timestamp)
        
        return timelines
    
    def _analyze_timeline(
        self,
        correlation_key: str,
        timeline: List[TimelineEvent]
    ) -> Optional[AdvancedCorrelatedEvent]:
        """Analyze timeline using rule engine and generate correlated event"""
        if len(timeline) < 2:
            return None
        
        # Evaluate timeline against rules
        matching_rules = self.rule_engine.evaluate(timeline)
        if not matching_rules:
            return None
        
        # Use best matching rule
        best_rule, confidence = matching_rules[0]
        
        # Detect attack sequences
        sequences = self._detect_sequences(timeline, best_rule)
        
        # Determine intent
        intent = self._determine_intent(timeline, best_rule)
        
        # Build context
        context = self._build_context(timeline)
        
        # Generate correlation ID
        correlation_id = self._generate_correlation_id(correlation_key, timeline)
        
        # Determine correlation strength
        correlation_strength = timeline[0].metadata.get('correlation_strength', 'WEAK')
        
        # Group evidence by source
        evidence_by_source = defaultdict(list)
        for event in timeline:
            evidence_by_source[event.source].append({
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity,
                'message': event.message
            })
        
        return AdvancedCorrelatedEvent(
            correlation_id=correlation_id,
            primary_correlation_key=correlation_key,
            correlation_strength=correlation_strength,
            timeline=timeline,
            attack_sequences=sequences,
            event_type=best_rule.event_type,
            severity=best_rule.severity,
            confidence_score=confidence,
            intent=intent,
            context=context,
            evidence_by_source=dict(evidence_by_source)
        )
    
    def _detect_sequences(self, timeline: List[TimelineEvent], rule: CorrelationRule) -> List[AttackSequence]:
        """Detect attack sequences in timeline"""
        sequences = []
        
        if len(timeline) < 2:
            return sequences
        
        # Calculate timing metrics
        total_duration = (timeline[-1].timestamp - timeline[0].timestamp).total_seconds()
        
        delays = []
        for i in range(len(timeline) - 1):
            delay = (timeline[i + 1].timestamp - timeline[i].timestamp).total_seconds()
            delays.append(delay)
        
        avg_delay = sum(delays) / len(delays) if delays else 0
        is_automated = avg_delay < 5.0
        
        # Create sequence
        sequence = AttackSequence(
            sequence_id=f"SEQ-{rule.rule_id}",
            pattern_name=rule.name,
            events=timeline,
            confidence=rule.base_confidence,
            total_duration_seconds=total_duration,
            average_delay_seconds=avg_delay,
            is_automated=is_automated,
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques
        )
        
        sequences.append(sequence)
        return sequences
    
    def _determine_intent(self, timeline: List[TimelineEvent], rule: CorrelationRule) -> str:
        """Determine attacker intent from timeline"""
        event_types = [event.event_type for event in timeline]
        
        if "sql_injection" in event_types or "data_exfiltration" in event_types:
            return "data_theft"
        elif "privilege_escalation" in event_types or "unauthorized_access" in event_types:
            return "privilege_escalation"
        elif "network_reject" in event_types and len(timeline) > 10:
            return "denial_of_service"
        else:
            return rule.event_type
    
    def _build_context(self, timeline: List[TimelineEvent]) -> Dict[str, Any]:
        """Build rich context from timeline"""
        return {
            'total_events': len(timeline),
            'sources_involved': list(set(e.source for e in timeline)),
            'severity_distribution': dict(Counter(e.severity for e in timeline)),
            'event_types': list(set(e.event_type for e in timeline)),
            'first_seen': timeline[0].timestamp.isoformat(),
            'last_seen': timeline[-1].timestamp.isoformat(),
            'duration_minutes': (timeline[-1].timestamp - timeline[0].timestamp).total_seconds() / 60
        }
    
    # ---- Helper Methods ----
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        return (ip.startswith('10.') or ip.startswith('192.168.') or 
                ip.startswith('172.') or ip.startswith('127.') or 
                ip == '0.0.0.0')
    
    def _get_source_type(self, log_group: str) -> str:
        """Determine source type from log group name"""
        lg_lower = log_group.lower()
        if 'vpc' in lg_lower or 'flowlog' in lg_lower:
            return 'vpc_flow'
        elif 'cloudtrail' in lg_lower:
            return 'cloudtrail'
        elif 'rds' in lg_lower or 'mysql' in lg_lower:
            return 'database'
        else:
            return 'application'
    
    def _classify_event_type(self, entry: LogEntry, source_type: str) -> str:
        """Classify event type from log entry"""
        text = ((entry.message or '') + ' ' + (entry.content or '')).lower()
        
        if source_type == 'vpc_flow':
            if 'reject' in text:
                return 'network_reject'
            return 'network_accept'
        
        elif source_type == 'cloudtrail':
            if 'denied' in text or 'accessdenied' in text:
                return 'api_deny'
            return 'api_call'
        
        elif source_type == 'database':
            if 'too many connections' in text:
                return 'too_many_connections'
            elif 'slow' in text or 'query_time' in text:
                return 'slow_query'
            return 'database_error'
        
        else:  # application
            if self._is_web_fuzzing_payload(text):
                return 'web_fuzzing'
            elif 'injection' in text:
                return 'sql_injection'
            elif 'path traversal' in text or '../' in text or '..\\' in text:
                return 'path_traversal'
            elif 'xss' in text or '<script' in text:
                return 'xss'
            elif any(marker in text for marker in ('[ssh_brute_force]', 'failed password', 'authentication failed', 'invalid user')):
                return 'brute_force'
            elif 'timeout' in text:
                return 'connection_timeout'
            elif 'unauthorized' in text or 'forbidden' in text:
                return 'unauthorized_access'
            elif re.search(r'\bhttp\s+[45]\d\d\b', text):
                return 'http_error'
            elif re.search(r'\bhttp\s+[123]\d\d\b', text):
                return 'http_request'
            return 'application_error'

    def _is_web_fuzzing_payload(self, text: str) -> bool:
        """Detect common web fuzzing, exploit probe, and scanner payloads."""
        web_fuzz_markers = [
            'sql_injection', 'path_traversal', '[attack:',
            'union select', ' or 1=1', "' or '1'='1", '" or "1"="1',
            '../', '..\\', '/etc/passwd', 'etc/passwd', 'boot.ini',
            '<script', 'javascript:', 'onerror=', 'onload=',
            'cmd=', 'exec=', ';cat ', '|cat ', '&&',
            '.git/', 'wp-admin', 'phpmyadmin', 'xmlrpc.php',
            'nikto', 'sqlmap', 'acunetix', 'dirbuster', 'gobuster', 'ffuf'
        ]
        return any(marker in text for marker in web_fuzz_markers)
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime"""
        if not timestamp_str:
            return None
        
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%d/%b/%Y:%H:%M:%S',
            '%b %d %H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                clean_ts = timestamp_str.replace('Z', '').split('+')[0].split()[0]
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue
        
        return None
    
    def _generate_correlation_id(self, correlation_key: str, timeline: List[TimelineEvent]) -> str:
        """Generate unique correlation ID"""
        data = f"{correlation_key}-{len(timeline)}-{timeline[0].timestamp}"
        return f"CORR-{hashlib.md5(data.encode()).hexdigest()[:12]}"
    
    def _extract_pattern_signature(self, text: str) -> str:
        """
        Extract pattern signature by removing variable parts.
        
        Example:
            "SQL injection at 10:23:15 from 203.0.113.42" 
            → "sql injection"
        """
        if not text:
            return ""
        
        # Remove timestamps
        text = re.sub(r'\d{2}:\d{2}:\d{2}', '', text)
        text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
        
        # Remove IPs
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '', text)
        
        # Remove numbers
        text = re.sub(r'\b\d+\b', '', text)
        
        # Extract key terms (lowercase, remove extra spaces)
        text = ' '.join(text.lower().split())
        
        # Keep only first 50 chars
        return text[:50]
