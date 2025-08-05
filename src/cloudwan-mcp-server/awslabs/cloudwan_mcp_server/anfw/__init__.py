"""AWS Network Firewall (ANFW) Integration Module.

This module provides comprehensive AWS Network Firewall analysis capabilities
for the CloudWAN MCP Server, including alert log analysis, flow log processing,
routing correlation, and policy evaluation.

Key Components:
- Alert log parsing and categorization
- Flow log analysis with traffic pattern detection
- Integration with existing CloudWAN routing analysis
- Firewall policy status and rule evaluation
"""

from typing import Any, Dict, List, Optional

__version__ = "0.1.0"
__author__ = "AWS Labs CloudWAN MCP Server Team"

# ANFW Integration Status
ANFW_INTEGRATION_STATUS = {
    "version": __version__,
    "status": "development",
    "capabilities": [
        "alert_log_analysis",
        "flow_log_analysis", 
        "routing_correlation",
        "policy_evaluation"
    ],
    "aws_services": [
        "network-firewall",
        "logs",
        "ec2"
    ]
}

__all__ = [
    "ANFW_INTEGRATION_STATUS",
]