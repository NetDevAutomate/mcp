"""AWS Network Firewall Alert Data Models.

This module defines data models and enumerations for ANFW alert analysis,
following AWS Labs patterns for type safety and data validation.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime


class AlertSeverity(Enum):
    """ANFW Alert Severity Levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertCategory(Enum):
    """ANFW Alert Categories for threat classification."""
    MALWARE = "MALWARE"
    INTRUSION_DETECTION = "INTRUSION_DETECTION"
    DLP = "DATA_LOSS_PREVENTION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    GEOLOCATION = "GEOLOCATION_BLOCK"
    REPUTATION = "REPUTATION_BLOCK"
    CUSTOM_RULE = "CUSTOM_RULE"


class ActionType(Enum):
    """ANFW Rule Actions."""
    ALERT = "ALERT"
    DROP = "DROP"
    REJECT = "REJECT"
    PASS = "PASS"


@dataclass
class NetworkContext:
    """Network context information for alert correlation."""
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    cloudwan_segment: Optional[str] = None
    transit_gateway_id: Optional[str] = None


@dataclass
class ANFWAlert:
    """AWS Network Firewall Alert data model."""
    alert_id: str
    timestamp: datetime
    firewall_name: str
    firewall_arn: str
    rule_group_name: str
    rule_name: str
    severity: AlertSeverity
    category: AlertCategory
    action: ActionType
    message: str
    network_context: NetworkContext
    raw_log_data: Dict[str, Any]
    
    # Analysis fields
    threat_score: Optional[float] = None
    false_positive_likelihood: Optional[float] = None
    correlation_id: Optional[str] = None
    related_alerts: List[str] = None
    
    def __post_init__(self):
        """Post-initialization validation."""
        if self.related_alerts is None:
            self.related_alerts = []


@dataclass
class AlertAnalysisSummary:
    """Summary of ANFW alert analysis results."""
    total_alerts: int
    analysis_period_start: datetime
    analysis_period_end: datetime
    severity_distribution: Dict[AlertSeverity, int]
    category_distribution: Dict[AlertCategory, int]
    top_threats: List[Dict[str, Any]]
    trending_patterns: List[Dict[str, Any]]
    recommendations: List[str]
    confidence_score: float