 SecurityRiskReport:
        """Perform comprehensive security risk analysis on policy rules."""
        self.rules = rules
        self.threats = []
        self.policy_gaps = []
        
        logger.info(f"Starting security analysis of {len(rules)} rules")
        
        # Core security analysis functions
        self._detect_dangerous_patterns()
        self._analyze_rule_ordering_vulnerabilities()
        self._assess_threat_scenarios()
        self._identify_policy_gaps()
        
        # Calculate overall security metrics
        overall_score = self._calculate_overall_security_score()
        threat_counts = self._count_threats_by_severity()
        attack_surface = self._analyze_attack_surface()
        compliance_results = self._assess_compliance_frameworks()
        
        # Generate comprehensive recommendations
        recommendations = self._generate_security_recommendations()
        
        report = SecurityRiskReport(
            overall_security_score=overall_score,
            threat_count=threat_counts,
            detected_threats=self.threats,
            policy_gaps=self.policy_gaps,
            compliance_assessments=compliance_results,
            attack_surface_analysis=attack_surface,
            recommendations=recommendations
        )
        
        logger.info(f"Security analysis complete. Score: {overall_score:.1f}, Threats: {len(self.threats)}")
        return report

    def _detect_dangerous_patterns(self) -> None:
        """Detect dangerous rule patterns that bypass security."""
        logger.debug("Analyzing dangerous rule patterns")
        
        for i, rule in enumerate(self.rules):
            # Pattern 1: Any/Any rules that bypass security
            if self._is_overly_permissive_rule(rule):
                threat = SecurityThreat(
                    threat_id=f"PERM_{i}",
                    vulnerability_type=VulnerabilityType.OVERLY_PERMISSIVE,
                    severity=ThreatSeverity.HIGH if rule.action in [FlowAction.ALLOW, FlowAction.PASS] else ThreatSeverity.MEDIUM,
                    title="Overly Permissive Rule Detected",
                    description=f"Rule allows broad access: {rule.raw_rule}",
                    affected_rules=[rule],
                    risk_score=self._calculate_rule_risk_score(rule),
                    mitigation_steps=[
                        "Narrow source IP ranges to specific subnets",
                        "Restrict port ranges to only required services",
                        "Add explicit deny rules for unused protocols",
                        "Implement network segmentation"
                    ],
                    compliance_impact=["PCI DSS 1.3.8", "NIST 800-53 SC-7"],
                    attack_scenarios=[
                        "Attackers can bypass intended network segmentation",
                        "Lateral movement between network segments",
                        "Unauthorized access to sensitive services"
                    ]
                )
                self.threats.append(threat)
            
            # Pattern 2: Missing logging on critical flows
            if self._missing_critical_logging(rule):
                threat = SecurityThreat(
                    threat_id=f"LOG_{i}",
                    vulnerability_type=VulnerabilityType.MISSING_LOGGING,
                    severity=ThreatSeverity.MEDIUM,
                    title="Missing Logging on Critical Flow",
                    description=f"Critical rule lacks logging: {rule.raw_rule}",
                    affected_rules=[rule],
                    risk_score=30.0,
                    mitigation_steps=[
                        "Add msg and sid options for logging",
                        "Enable flow logging for all DENY rules",
                        "Implement centralized log collection"
                    ],
                    compliance_impact=["SOX", "HIPAA", "PCI DSS 10.2"],
                    attack_scenarios=[
                        "Security incidents go undetected",
                        "Forensic analysis impossible",
                        "Compliance violations"
                    ]
                )
                self.threats.append(threat)

    def _analyze_rule_ordering_vulnerabilities(self) -> None:
        """Analyze rule ordering for security bypasses."""
        logger.debug("Analyzing rule ordering vulnerabilities")
        
        for i, rule in enumerate(self.rules):
            # Check if rule is unreachable due to earlier broader rules
            shadowing_rules = []
            for j in range(i):
                earlier_rule = self.rules[j]
                if self._rule_shadows_another(earlier_rule, rule):
                    shadowing_rules.append(earlier_rule)
            
            if shadowing_rules:
                threat = SecurityThreat(
                    threat_id=f"ORDER_{i}",
                    vulnerability_type=VulnerabilityType.UNREACHABLE_RULE,
                    severity=ThreatSeverity.HIGH if rule.action in [FlowAction.DENY, FlowAction.DROP] else ThreatSeverity.MEDIUM,
                    title="Unreachable Security Rule",
                    description=f"Rule {i+1} is shadowed by earlier rules",
                    affected_rules=[rule] + shadowing_rules,
                    risk_score=60.0,
                    mitigation_steps=[
                        "Reorder rules to place specific rules before general ones",
                        "Review rule precedence and priority",
                        "Remove redundant rules"
                    ],
                    compliance_impact=["Security policy effectiveness"],
                    attack_scenarios=[
                        "Security controls are bypassed",
                        "Intended blocking rules never execute",
                        "False sense of security"
                    ]
                )
                self.threats.append(threat)
            
            # Check for security bypass through permissive rules after restrictive ones
            if rule.action in [FlowAction.ALLOW, FlowAction.PASS]:
                for j in range(i + 1, len(self.rules)):
                    later_rule = self.rules[j]
                    if (later_rule.action in [FlowAction.DENY, FlowAction.DROP] and
                        self._rules_overlap(rule, later_rule)):
                        threat = SecurityThreat(
                            threat_id=f"BYPASS_{i}_{j}",
                            vulnerability_type=VulnerabilityType.RULE_ORDERING_BYPASS,
                            severity=ThreatSeverity.HIGH,
                            title="Security Policy Bypass",
                            description=f"Permissive rule {i+1} may bypass restrictive rule {j+1}",
                            affected_rules=[rule, later_rule],
                            risk_score=75.0,
                            mitigation_steps=[
                                "Place deny rules before allow rules",
                                "Use more specific match criteria",
                                "Implement default-deny policy"
                            ],
                            compliance_impact=["Security architecture violation"],
                            attack_scenarios=[
                                "Attackers exploit rule precedence",
                                "Security controls are circumvented",
                                "Unauthorized network access"
                            ]
                        )
                        self.threats.append(threat)

    def _assess_threat_scenarios(self) -> None:
        """Assess advanced threat scenarios like lateral movement and data exfiltration."""
        logger.debug("Assessing advanced threat scenarios")
        
        # Lateral movement analysis
        self._detect_lateral_movement_risks()
        
        # Data exfiltration analysis
        self._detect_data_exfiltration_risks()
        
        # Command and control analysis
        self._detect_cc_risks()

    def _detect_lateral_movement_risks(self) -> None:
        """Detect rules that could enable lateral movement."""
        internal_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        
        for i, rule in enumerate(self.rules):
            if rule.action in [FlowAction.ALLOW, FlowAction.PASS]:
                # Check for internal-to-internal communication on critical ports
                if (self._rule_affects_internal_networks(rule, internal_networks) and
                    self._rule_affects_critical_ports(rule)):
                    
                    threat = SecurityThreat(
                        threat_id=f"LATERAL_{i}",
                        vulnerability_type=VulnerabilityType.LATERAL_MOVEMENT,
                        severity=ThreatSeverity.HIGH,
                        title="Lateral Movement Risk",
                        description=f"Rule allows internal network traversal: {rule.raw_rule}",
                        affected_rules=[rule],
                        risk_score=80.0,
                        mitigation_steps=[
                            "Implement network micro-segmentation",
                            "Restrict admin protocol access (SSH, RDP, WinRM)",
                            "Use zero-trust network architecture",
                            "Add explicit deny rules between segments"
                        ],
                        compliance_impact=["NIST Zero Trust", "ISO 27001 A.13.1"],
                        attack_scenarios=[
                            "Compromised host spreads to other systems",
                            "Privilege escalation across network segments",
                            "Data access beyond initial breach point"
                        ]
                    )
                    self.threats.append(threat)

    def _detect_data_exfiltration_risks(self) -> None:
        """Detect rules that could enable data exfiltration."""
        for i, rule in enumerate(self.rules):
            if (rule.action in [FlowAction.ALLOW, FlowAction.PASS] and
                rule.direction.value in ["->", "<>"] and
                self._rule_enables_exfiltration(rule)):
                
                threat = SecurityThreat(
                    threat_id=f"EXFIL_{i}",
                    vulnerability_type=VulnerabilityType.DATA_EXFILTRATION,
                    severity=ThreatSeverity.HIGH,
                    title="Data Exfiltration Risk",
                    description=f"Rule allows potential data exfiltration: {rule.raw_rule}",
                    affected_rules=[rule],
                    risk_score=70.0,
                    mitigation_steps=[
                        "Implement data loss prevention (DLP) controls",
                        "Monitor and restrict large outbound transfers",
                        "Add content inspection for sensitive data",
                        "Limit outbound connectivity to approved destinations"
                    ],
                    compliance_impact=["GDPR Article 32", "SOX", "PCI DSS 3.4"],
                    attack_scenarios=[
                        "Sensitive data transmitted to external systems",
                        "Intellectual property theft",
                        "Customer data breach via network channels"
                    ]
                )
                self.threats.append(threat)

    def _detect_cc_risks(self) -> None:
        """Detect command and control communication risks."""
        for i, rule in enumerate(self.rules):
            if (rule.action in [FlowAction.ALLOW, FlowAction.PASS] and
                self._rule_enables_cc_communication(rule)):
                
                threat = SecurityThreat(
                    threat_id=f"CC_{i}",
                    vulnerability_type=VulnerabilityType.COMMAND_CONTROL,
                    severity=ThreatSeverity.CRITICAL,
                    title="Command & Control Communication Risk",
                    description=f"Rule may allow C&C communication: {rule.raw_rule}",
                    affected_rules=[rule],
                    risk_score=90.0,
                    mitigation_steps=[
                        "Block known C&C ports and protocols",
                        "Implement DNS filtering and monitoring",
                        "Use threat intelligence feeds",
                        "Monitor for suspicious outbound connections"
                    ],
                    compliance_impact=["Security incident response", "Threat detection"],
                    attack_scenarios=[
                        "Malware maintains persistent access",
                        "Remote command execution by attackers",
                        "Botnet participation and control"
                    ]
                )
                self.threats.append(threat)

    def _identify_policy_gaps(self) -> None:
        """Identify gaps in security policy coverage."""
        logger.debug("Identifying policy gaps")
        
        # Check for missing default deny
        if not self._has_default_deny_policy():
            gap = PolicyGap(
                gap_id="GAP_DEFAULT_DENY",
                gap_type="Missing Default Deny",
                description="No default deny rule found - may allow unintended traffic",
                affected_networks=["0.0.0.0/0"],
                affected_ports=[],
                risk_level=ThreatSeverity.HIGH,
                recommendations=[
                    "Add default deny rule at end of policy",
                    "Ensure all traffic is explicitly allowed",
                    "Implement default-deny security posture"
                ]
            )
            self.policy_gaps.append(gap)
        
        # Check for uncovered critical services
        uncovered_services = self._find_uncovered_critical_services()
        if uncovered_services:
            gap = PolicyGap(
                gap_id="GAP_CRITICAL_SERVICES",
                gap_type="Uncovered Critical Services",
                description=f"Critical services lack explicit rules: {', '.join(uncovered_services)}",
                affected_networks=["internal"],
                affected_ports=[self.critical_ports[port] for port, service in self.critical_ports.items()
                               if service in uncovered_services],
                risk_level=ThreatSeverity.MEDIUM,
                recommendations=[
                    "Add explicit rules for all critical services",
                    "Document security requirements for each service",
                    "Implement service-specific access controls"
                ]
            )
            self.policy_gaps.append(gap)

    def _calculate_overall_security_score(self) -> float:
        """Calculate overall security score (0-100)."""
        base_score = 100.0
        
        # Deduct for threats by severity
        for threat in self.threats:
            if threat.severity == ThreatSeverity.CRITICAL:
                base_score -= 25.0
            elif threat.severity == ThreatSeverity.HIGH:
                base_score -= 15.0
            elif threat.severity == ThreatSeverity.MEDIUM:
                base_score -= 8.0
            elif threat.severity == ThreatSeverity.LOW:
                base_score -= 3.0
        
        # Deduct for policy gaps
        for gap in self.policy_gaps:
            if gap.risk_level == ThreatSeverity.HIGH:
                base_score -= 10.0
            elif gap.risk_level == ThreatSeverity.MEDIUM:
                base_score -= 5.0
        
        # Bonus for good security practices
        if self._has_comprehensive_logging():
            base_score += 5.0
        
        if self._has_defense_in_depth():
            base_score += 5.0
        
        return max(0.0, min(100.0, base_score))

    def _count_threats_by_severity(self) -> Dict[ThreatSeverity, int]:
        """Count threats by severity level."""
        counts = {severity: 0 for severity in ThreatSeverity}
        for threat in self.threats:
            counts[threat.severity] += 1
        return counts

    def _analyze_attack_surface(self) -> Dict[str, Any]:
        """Analyze the attack surface exposed by the policy."""
        exposed_ports = set()
        exposed_protocols = set()
        external_access_rules = []
        
        for rule in self.rules:
            if rule.action in [FlowAction.ALLOW, FlowAction.PASS]:
                # Check if rule allows external access
                if self._rule_allows_external_access(rule):
                    external_access_rules.append(rule)
                    exposed_protocols.add(rule.protocol)
                    
                    # Extract exposed ports
                    if rule.dest_port.start == rule.dest_port.end:
                        exposed_ports.add(rule.dest_port.start)
                    else:
                        exposed_ports.update(range(rule.dest_port.start,
                                                 min(rule.dest_port.end + 1, rule.dest_port.start + 100)))
        
        return {
            "exposed_ports": sorted(list(exposed_ports))[:50],  # Limit output
            "exposed_protocols": list(exposed_protocols),
            "external_access_rules": len(external_access_rules),
            "risk_assessment": "HIGH" if len(exposed_ports) > 10 else "MEDIUM" if exposed_ports else "LOW"
        }

    def _assess_compliance_frameworks(self) -> List[ComplianceAssessment]:
        """Assess compliance with security frameworks."""
        frameworks = []
        
        # PCI DSS Assessment
        pci_score, pci_passed, pci_failed = self._assess_pci_dss_compliance()
        frameworks.append(ComplianceAssessment(
            framework="PCI DSS",
            overall_score=pci_score,
            passed_controls=pci_passed,
            failed_controls=pci_failed,
            recommendations=self._get_pci_recommendations(pci_failed)
        ))
        
        # NIST Cybersecurity Framework
        nist_score, nist_passed, nist_failed = self._assess_nist_compliance()
        frameworks.append(ComplianceAssessment(
            framework="NIST CSF",
            overall_score=nist_score,
            passed_controls=nist_passed,
            failed_controls=nist_failed,
            recommendations=self._get_nist_recommendations(nist_failed)
        ))
        
        return frameworks

    def _generate_security_recommendations(self) -> List[str]:
        """Generate comprehensive security recommendations."""
        recommendations = []
        
        # High-priority recommendations based on threats
        critical_threats = [t for t in self.threats if t.severity == ThreatSeverity.CRITICAL]
        if critical_threats:
            recommendations.append("URGENT: Address critical security threats immediately")
        
        high_threats = [t for t in self.threats if t.severity == ThreatSeverity.HIGH]
        if len(high_threats) > 3:
            recommendations.append("High priority: Multiple high-severity threats detected")
        
        # Policy structure recommendations
        if not self._has_default_deny_policy():
            recommendations.append("Implement default-deny policy as security baseline")
        
        if not self._has_comprehensive_logging():
            recommendations.append("Enable comprehensive logging for security monitoring")
        
        # Advanced security recommendations
        if self._needs_network_segmentation():
            recommendations.append("Implement network micro-segmentation for zero-trust architecture")
        
        recommendations.append("Regular security policy reviews and updates recommended")
        recommendations.append("Consider implementing automated threat detection and response")
        
        return recommendations

    # Helper methods for security analysis
    
    def _is_overly_permissive_rule(self, rule: SuricataRule) -> bool:
        """Check if rule is overly permissive."""
        # Check for any/any patterns
        broad_source = any(str(net) in ["0.0.0.0/0", "::/0"] or net.prefixlen < 16
                          for net in rule.source_ip.networks)
        broad_dest = any(str(net) in ["0.0.0.0/0", "::/0"] or net.prefixlen < 16
                        for net in rule.dest_ip.networks)
        wide_port_range = (rule.dest_port.end - rule.dest_port.start) > 1000
        
        return broad_source and broad_dest and wide_port_range

    def _missing_critical_logging(self, rule: SuricataRule) -> bool:
        """Check if critical rule lacks logging."""
        is_critical_action = rule.action in [FlowAction.DENY, FlowAction.DROP, FlowAction.ALERT]
        has_logging = "msg" in rule.options or "sid" in rule.options
        return is_critical_action and not has_logging

    def _rule_shadows_another(self, earlier_rule: SuricataRule, later_rule: SuricataRule) -> bool:
        """Check if earlier rule completely shadows a later rule."""
        # Simplified shadowing detection - would need more complex logic for full implementation
        return (earlier_rule.protocol == later_rule.protocol and
                self._ip_spec_contains(earlier_rule.source_ip, later_rule.source_ip) and
                self._ip_spec_contains(earlier_rule.dest_ip, later_rule.dest_ip) and
                self._port_range_contains(earlier_rule.dest_port, later_rule.dest_port))

    def _rules_overlap(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if two rules have overlapping conditions."""
        # Simplified overlap detection
        return (rule1.protocol == rule2.protocol or
                rule1.protocol == "IP" or rule2.protocol == "IP")

    def _rule_affects_internal_networks(self, rule: SuricataRule, internal_nets: List[str]) -> bool:
        """Check if rule affects internal network communications."""
        for net_str in internal_nets:
            internal_net = ipaddress.ip_network(net_str)
            for src_net in rule.source_ip.networks:
                for dst_net in rule.dest_ip.networks:
                    if (src_net.subnet_of(internal_net) and dst_net.subnet_of(internal_net)):
                        return True
        return False

    def _rule_affects_critical_ports(self, rule: SuricataRule) -> bool:
        """Check if rule affects critical administrative ports."""
        critical_admin_ports = [22, 23, 135, 139, 389, 445, 3389, 5985, 5986]
        return any(rule.dest_port.matches(port) for port in critical_admin_ports)

    def _rule_enables_exfiltration(self, rule: SuricataRule) -> bool:
        """Check if rule could enable data exfiltration."""
        exfil_ports = self.exfiltration_patterns["high_risk_ports"]
        return any(rule.dest_port.matches(port) for port in exfil_ports)

    def _rule_enables_cc_communication(self, rule: SuricataRule) -> bool:
        """Check if rule could enable C&C communication."""
        cc_ports = self.cc_indicators["ports"]
        return any(rule.dest_port.matches(port) for port in cc_ports)

    def _rule_allows_external_access(self, rule: SuricataRule) -> bool:
        """Check if rule allows access from external networks."""
        # Check if source includes external networks (non-RFC1918)
        for net in rule.source_ip.networks:
            if not net.is_private:
                return True
        return False

    def _has_default_deny_policy(self) -> bool:
        """Check if policy has a default deny rule."""
        return any(rule.action in [FlowAction.DENY, FlowAction.DROP] and
                  any(str(net) == "0.0.0.0/0" for net in rule.source_ip.networks)
                  for rule in self.rules)

    def _has_comprehensive_logging(self) -> bool:
        """Check if policy has comprehensive logging."""
        logged_rules = sum(1 for rule in self.rules if "msg" in rule.options)
        return logged_rules / len(self.rules) > 0.8 if self.rules else False

    def _has_defense_in_depth(self) -> bool:
        """Check if policy implements defense in depth."""
        # Multiple layers of security controls
        has_network_controls = any(rule.action in [FlowAction.DENY, FlowAction.DROP]
                                 for rule in self.rules)
        has_monitoring = any("msg" in rule.options for rule in self.rules)
        return has_network_controls and has_monitoring

    def _needs_network_segmentation(self) -> bool:
        """Determine if network segmentation is needed."""
        # If many internal-to-internal allow rules exist
        internal_rules = sum(1 for rule in self.rules
                           if rule.action in [FlowAction.ALLOW, FlowAction.PASS] and
                           self._rule_affects_internal_networks(rule, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]))
        return internal_rules > 5

    def _find_uncovered_critical_services(self) -> List[str]:
        """Find critical services not covered by explicit rules."""
        covered_ports = set()
        for rule in self.rules:
            if rule.dest_port.start == rule.dest_port.end:
                covered_ports.add(rule.dest_port.start)
        
        uncovered = []
        for port, service in self.critical_ports.items():
            if port not in covered_ports:
                uncovered.append(service)
        
        return uncovered[:10]  # Limit results

    def _calculate_rule_risk_score(self, rule: SuricataRule) -> float:
        """Calculate risk score for individual rule."""
        base_score = 50.0
        
        if rule.action in [FlowAction.ALLOW, FlowAction.PASS]:
            base_score += 20.0
        
        # Check breadth of rule
        broad_source = any(net.prefixlen < 16 for net in rule.source_ip.networks if net.version == 4)
        if broad_source:
            base_score += 15.0
        
        wide_ports = (rule.dest_port.end - rule.dest_port.start) > 100
        if wide_ports:
            base_score += 10.0
        
        return min(100.0, base_score)

    def _assess_pci_dss_compliance(self) -> Tuple[float, List[str], List[str]]:
        """Assess PCI DSS compliance."""
        passed = []
        failed = []
        
        # Requirement 1.3.8: Restrict inbound and outbound traffic
        if self._has_traffic_restrictions():
            passed.append("1.3.8 - Traffic restrictions implemented")
        else:
            failed.append("1.3.