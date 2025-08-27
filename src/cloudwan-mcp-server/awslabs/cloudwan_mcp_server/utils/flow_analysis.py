# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Advanced 5-tuple flow analysis module for CloudWAN MCP Server."""

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..consts import sanitize_error_message
from ..utils.logger import get_logger

logger = get_logger("flow_analysis")


class FlowAction(Enum):
    """Flow actions supported by the analysis engine."""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"
    ALERT = "alert"
    PASS = "pass"
    LOG = "log"


class RulePriority(Enum):
    """Rule priority levels."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class FlowDirection(Enum):
    """Flow direction indicators."""
    UNIDIRECTIONAL = "->"
    BIDIRECTIONAL = "<>"
    REVERSE = "<-"


@dataclass
class PortRange:
    """Represents a port or port range specification."""
    start: int
    end: int
    negated: bool = False
    
    @classmethod
    def parse(cls, port_spec: str) -> "PortRange":
        """Parse port specification (80, 1:1024, !80, any)."""
        port_spec = port_spec.strip()
        
        if port_spec.lower() == "any":
            return cls(1, 65535)
        
        negated = port_spec.startswith("!")
        if negated:
            port_spec = port_spec[1:]
        
        if ":" in port_spec:
            start, end = map(int, port_spec.split(":", 1))
            return cls(start, end, negated)
        else:
            port = int(port_spec)
            return cls(port, port, negated)
    
    def matches(self, port: int) -> bool:
        """Check if a port matches this range."""
        in_range = self.start <= port <= self.end
        return not in_range if self.negated else in_range


@dataclass
class IPSpec:
    """Represents IP address specification with CIDR support."""
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network]
    negated: bool = False
    variables: List[str] = field(default_factory=list)
    
    @classmethod
    def parse(cls, ip_spec: str, variables: Optional[Dict[str, str]] = None) -> "IPSpec":
        """Parse IP specification (10.0.0.1, 10.0.0.0/24, $HOME_NET, !192.168.0.0/16)."""
        variables = variables or {}
        ip_spec = ip_spec.strip()
        
        if ip_spec.lower() == "any":
            return cls([ipaddress.IPv4Network("0.0.0.0/0")])
        
        negated = ip_spec.startswith("!")
        if negated:
            ip_spec = ip_spec[1:]
        
        networks = []
        spec_vars = []
        
        # Handle comma-separated IPs
        for part in ip_spec.split(","):
            part = part.strip()
            
            # Handle variables like $HOME_NET
            if part.startswith("$"):
                var_name = part[1:]
                spec_vars.append(var_name)
                if var_name in variables:
                    var_value = variables[var_name]
                    for sub_part in var_value.split(","):
                        try:
                            networks.append(ipaddress.ip_network(sub_part.strip(), strict=False))
                        except ValueError:
                            logger.warning(f"Invalid IP in variable {var_name}: {sub_part}")
                continue
            
            # Handle direct IP/CIDR
            try:
                if "/" not in part:
                    # Single IP - convert to /32 or /128 network
                    addr = ipaddress.ip_address(part)
                    prefix_len = 32 if addr.version == 4 else 128
                    networks.append(ipaddress.ip_network(f"{part}/{prefix_len}"))
                else:
                    networks.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                logger.warning(f"Invalid IP specification: {part}")
        
        return cls(networks, negated, spec_vars)
    
    def matches(self, ip: str) -> bool:
        """Check if an IP matches this specification."""
        try:
            target_ip = ipaddress.ip_address(ip)
            
            for network in self.networks:
                if target_ip in network:
                    return not self.negated
            
            return self.negated
        except ValueError:
            return False


@dataclass
class SuricataRule:
    """Represents a parsed Suricata rule with enhanced matching capabilities."""
    action: FlowAction
    protocol: str
    source_ip: IPSpec
    source_port: PortRange
    direction: FlowDirection
    dest_ip: IPSpec
    dest_port: PortRange
    options: Dict[str, Any]
    raw_rule: str
    priority: int = 3
    sid: Optional[int] = None
    rev: Optional[int] = None
    
    @classmethod
    def parse(cls, rule_text: str, variables: Optional[Dict[str, str]] = None) -> Optional["SuricataRule"]:
        """Parse a Suricata rule with comprehensive option support."""
        rule_text = rule_text.strip()
        
        if not rule_text or rule_text.startswith("#"):
            return None
        
        # Basic rule pattern: action protocol src_ip src_port direction dst_ip dst_port (options)
        pattern = r'^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)\s*\((.*)\)$'
        match = re.match(pattern, rule_text)
        
        if not match:
            logger.warning(f"Failed to parse rule: {rule_text}")
            return None
        
        try:
            action_str, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_str = match.groups()
            
            # Parse components
            action = FlowAction(action_str.lower())
            source_ip = IPSpec.parse(src_ip, variables)
            source_port = PortRange.parse(src_port)
            flow_direction = FlowDirection(direction)
            dest_ip = IPSpec.parse(dst_ip, variables)
            dest_port = PortRange.parse(dst_port)
            
            # Parse options
            options = cls._parse_options(options_str)
            
            # Extract priority, sid, rev from options
            priority = int(options.get("priority", 3))
            sid = int(options["sid"]) if "sid" in options else None
            rev = int(options["rev"]) if "rev" in options else None
            
            return cls(
                action=action,
                protocol=protocol.upper(),
                source_ip=source_ip,
                source_port=source_port,
                direction=flow_direction,
                dest_ip=dest_ip,
                dest_port=dest_port,
                options=options,
                raw_rule=rule_text,
                priority=priority,
                sid=sid,
                rev=rev
            )
            
        except (ValueError, KeyError) as e:
            logger.error(f"Error parsing rule: {sanitize_error_message(str(e))}")
            return None
    
    @staticmethod
    def _parse_options(options_str: str) -> Dict[str, Any]:
        """Parse Suricata rule options."""
        options = {}
        
        # Split by semicolon but respect quoted strings
        parts = []
        current = ""
        in_quotes = False
        
        for char in options_str:
            if char == '"' and (not current or current[-1] != '\\'):
                in_quotes = not in_quotes
            elif char == ';' and not in_quotes:
                if current.strip():
                    parts.append(current.strip())
                current = ""
                continue
            current += char
        
        if current.strip():
            parts.append(current.strip())
        
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                key = key.strip()
                value = value.strip().strip('"')
                options[key] = value
            else:
                options[part.strip()] = True
        
        return options
    
    def matches_flow(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """Check if this rule matches a 5-tuple flow."""
        # Protocol check (case-insensitive)
        if self.protocol.upper() != protocol.upper() and self.protocol.upper() != "IP":
            return False
        
        # Directional matching
        if self.direction == FlowDirection.BIDIRECTIONAL:
            # Check both directions
            forward_match = (
                self.source_ip.matches(src_ip) and
                self.source_port.matches(src_port) and
                self.dest_ip.matches(dst_ip) and
                self.dest_port.matches(dst_port)
            )
            
            reverse_match = (
                self.source_ip.matches(dst_ip) and
                self.source_port.matches(dst_port) and
                self.dest_ip.matches(src_ip) and
                self.dest_port.matches(src_port)
            )
            
            return forward_match or reverse_match
        else:
            # Unidirectional matching
            return (
                self.source_ip.matches(src_ip) and
                self.source_port.matches(src_port) and
                self.dest_ip.matches(dst_ip) and
                self.dest_port.matches(dst_port)
            )


@dataclass
class FlowAnalysisResult:
    """Result of flow analysis including security assessment."""
    flow_id: str
    decision: FlowAction
    matching_rules: List[SuricataRule]
    conflicts: List[Tuple[SuricataRule, SuricataRule]]
    security_score: float
    risk_level: str
    performance_impact: str
    recommendations: List[str]


class FlowAnalysisEngine:
    """Advanced 5-tuple flow analysis engine with security focus."""
    
    def __init__(self):
        self.rules: List[SuricataRule] = []
        self.variables: Dict[str, str] = {
            "HOME_NET": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
            "EXTERNAL_NET": "!$HOME_NET",
            "HTTP_PORTS": "80,8080,8000,8008",
            "HTTPS_PORTS": "443,8443",
            "SSH_PORTS": "22",
            "DNS_PORTS": "53",
        }
        self.rule_conflicts: List[Tuple[SuricataRule, SuricataRule]] = []
    
    def add_rules(self, rules_text: str) -> Dict[str, Any]:
        """Add rules from text and analyze for conflicts."""
        new_rules = []
        parse_errors = []
        
        for line_num, line in enumerate(rules_text.strip().split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            rule = SuricataRule.parse(line, self.variables)
            if rule:
                new_rules.append(rule)
            else:
                parse_errors.append(f"Line {line_num}: Failed to parse rule")
        
        self.rules.extend(new_rules)
        self._analyze_rule_conflicts()
        
        return {
            "rules_added": len(new_rules),
            "total_rules": len(self.rules),
            "parse_errors": parse_errors,
            "conflicts_detected": len(self.rule_conflicts)
        }
    
    def analyze_flow(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> FlowAnalysisResult:
        """Perform comprehensive flow analysis."""
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        
        # Find matching rules
        matching_rules = []
        for rule in self.rules:
            if rule.matches_flow(src_ip, src_port, dst_ip, dst_port, protocol):
                matching_rules.append(rule)
        
        # Sort by priority (lower number = higher priority)
        matching_rules.sort(key=lambda r: (r.priority, r.sid or 999999))
        
        # Determine final decision based on rule precedence
        decision = self._determine_decision(matching_rules)
        
        # Find conflicts among matching rules
        flow_conflicts = []
        for i, rule1 in enumerate(matching_rules):
            for rule2 in matching_rules[i+1:]:
                if self._rules_conflict(rule1, rule2):
                    flow_conflicts.append((rule1, rule2))
        
        # Security assessment
        security_score = self._calculate_security_score(matching_rules, flow_conflicts)
        risk_level = self._assess_risk_level(security_score, matching_rules)
        performance_impact = self._assess_performance_impact(matching_rules)
        recommendations = self._generate_recommendations(matching_rules, flow_conflicts, decision)
        
        return FlowAnalysisResult(
            flow_id=flow_id,
            decision=decision,
            matching_rules=matching_rules,
            conflicts=flow_conflicts,
            security_score=security_score,
            risk_level=risk_level,
            performance_impact=performance_impact,
            recommendations=recommendations
        )
    
    def _analyze_rule_conflicts(self) -> None:
        """Detect conflicts between all rules."""
        self.rule_conflicts = []
        
        for i, rule1 in enumerate(self.rules):
            for rule2 in self.rules[i+1:]:
                if self._rules_conflict(rule1, rule2):
                    self.rule_conflicts.append((rule1, rule2))
    
    def _rules_conflict(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if two rules conflict with each other."""
        # Rules conflict if they have overlapping match conditions but different actions
        if rule1.action == rule2.action:
            return False
        
        # Check if rules have overlapping match conditions
        return self._rules_overlap(rule1, rule2)
    
    def _rules_overlap(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if two rules have overlapping match conditions."""
        # For simplicity, check if they match the same protocol
        if rule1.protocol != rule2.protocol and rule1.protocol != "IP" and rule2.protocol != "IP":
            return False
        
        # Check IP overlap (simplified - would need more complex logic for full overlap detection)
        src_overlap = self._ip_specs_overlap(rule1.source_ip, rule2.source_ip)
        dst_overlap = self._ip_specs_overlap(rule1.dest_ip, rule2.dest_ip)
        
        # Check port overlap
        src_port_overlap = self._port_ranges_overlap(rule1.source_port, rule2.source_port)
        dst_port_overlap = self._port_ranges_overlap(rule1.dest_port, rule2.dest_port)
        
        return src_overlap and dst_overlap and src_port_overlap and dst_port_overlap
    
    def _ip_specs_overlap(self, spec1: IPSpec, spec2: IPSpec) -> bool:
        """Check if two IP specifications overlap."""
        # Simplified overlap check - would need more complex logic for full implementation
        for net1 in spec1.networks:
            for net2 in spec2.networks:
                if net1.overlaps(net2):
                    return True
        return False
    
    def _port_ranges_overlap(self, range1: PortRange, range2: PortRange) -> bool:
        """Check if two port ranges overlap."""
        if range1.negated or range2.negated:
            # Complex logic needed for negated ranges
            return True
        
        return not (range1.end < range2.start or range2.end < range1.start)
    
    def _determine_decision(self, matching_rules: List[SuricataRule]) -> FlowAction:
        """Determine final decision based on rule precedence."""
        if not matching_rules:
            return FlowAction.ALLOW  # Default allow
        
        # Security-first precedence: DENY/DROP > ALERT > ALLOW/PASS
        for rule in matching_rules:
            if rule.action in [FlowAction.DENY, FlowAction.DROP, FlowAction.REJECT]:
                return rule.action
        
        for rule in matching_rules:
            if rule.action == FlowAction.ALERT:
                return rule.action
        
        # Return first match if no blocking actions found
        return matching_rules[0].action
    
    def _calculate_security_score(self, matching_rules: List[SuricataRule], conflicts: List[Tuple[SuricataRule, SuricataRule]]) -> float:
        """Calculate security score (0-100) based on rule analysis."""
        base_score = 100.0
        
        # Deduct for conflicts
        base_score -= len(conflicts) * 10
        
        # Deduct for overly permissive rules
        for rule in matching_rules:
            if rule.action in [FlowAction.ALLOW, FlowAction.PASS]:
                # Check if rule is overly broad
                if (rule.source_ip.networks and
                    any(net.prefixlen < 16 for net in rule.source_ip.networks if net.version == 4)):
                    base_score -= 5
        
        # Bonus for explicit deny rules
        deny_rules = sum(1 for rule in matching_rules if rule.action in [FlowAction.DENY, FlowAction.DROP])
        if deny_rules > 0:
            base_score += min(deny_rules * 2, 10)
        
        return max(0.0, min(100.0, base_score))
    
    def _assess_risk_level(self, security_score: float, matching_rules: List[SuricataRule]) -> str:
        """Assess risk level based on security score and rule analysis."""
        if security_score >= 90:
            return "LOW"
        elif security_score >= 70:
            return "MEDIUM"
        elif security_score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _assess_performance_impact(self, matching_rules: List[SuricataRule]) -> str:
        """Assess performance impact of rule processing."""
        if len(matching_rules) > 10:
            return "HIGH"
        elif len(matching_rules) > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, matching_rules: List[SuricataRule], conflicts: List[Tuple[SuricataRule, SuricataRule]], decision: FlowAction) -> List[str]:
        """Generate security and performance recommendations."""
        recommendations = []
        
        # Conflict recommendations
        if conflicts:
            recommendations.append(f"Resolve {len(conflicts)} rule conflicts to improve policy clarity")
        
        # Overly broad rule recommendations
        broad_rules = [
            rule for rule in matching_rules
            if rule.source_ip.networks and any(net.prefixlen < 16 for net in rule.source_ip.networks if net.version == 4)
        ]
        if broad_rules:
            recommendations.append("Consider narrowing overly broad source IP ranges for better security")
        
        # Performance recommendations
        if len(matching_rules) > 10:
            recommendations.append("Consider consolidating rules to improve processing performance")
        
        # Security recommendations
        if decision == FlowAction.ALLOW and not any(rule.action == FlowAction.ALERT for rule in matching_rules):
            recommendations.append("Consider adding logging/alerting for allowed flows")
        
        return recommendations
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get comprehensive policy analysis summary."""
        total_rules = len(self.rules)
        action_counts = {}
        
        for rule in self.rules:
            action_counts[rule.action.value] = action_counts.get(rule.action.value, 0) + 1
        
        return {
            "total_rules": total_rules,
            "action_distribution": action_counts,
            "conflicts_detected": len(self.rule_conflicts),
            "variables_defined": len(self.variables),
            "security_coverage": self._calculate_policy_coverage()
        }
    
    def _calculate_policy_coverage(self) -> Dict[str, Any]:
        """Calculate policy coverage metrics."""
        protocols = set(rule.protocol for rule in self.rules)
        has_default_deny = any(
            rule.action in [FlowAction.DENY, FlowAction.DROP] and
            rule.source_ip.networks and
            any(str(net) == "0.0.0.0/0" for net in rule.source_ip.networks)
            for rule in self.rules
        )
        
        return {
            "protocols_covered": list(protocols),
            "has_default_deny": has_default_deny,
            "logging_enabled": any("msg" in rule.options for rule in self.rules)
        }