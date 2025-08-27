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

"""BGP analysis engine for CloudWAN implementing RFC 4271 BGP-4 specifications."""

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .logger import get_logger

logger = get_logger("bgp_analysis")


class BGPOrigin(Enum):
    """BGP Origin attribute values per RFC 4271."""
    IGP = "i"       # Interior Gateway Protocol
    EGP = "e"       # Exterior Gateway Protocol  
    INCOMPLETE = "?"  # Incomplete


class BGPCommunity(Enum):
    """Well-known BGP community values."""
    NO_EXPORT = "65535:65281"
    NO_ADVERTISE = "65535:65282"
    NO_EXPORT_SUBCONFED = "65535:65283"


@dataclass
class BGPPathAttribute:
    """BGP Path Attributes per RFC 4271."""
    # Well-known mandatory attributes
    origin: Optional[BGPOrigin] = None
    as_path: List[int] = field(default_factory=list)
    next_hop: Optional[str] = None
    
    # Well-known discretionary attributes
    local_pref: Optional[int] = None
    atomic_aggregate: bool = False
    
    # Optional transitive attributes
    aggregator: Optional[Tuple[int, str]] = None  # (ASN, IP)
    communities: List[str] = field(default_factory=list)
    
    # Optional non-transitive attributes
    med: Optional[int] = None  # Multi-Exit Discriminator
    
    # Additional AWS-specific attributes
    weight: Optional[int] = None  # Cisco/AWS specific
    as_path_prepend_count: int = 0


@dataclass
class BGPRoute:
    """Represents a BGP route with full path attributes."""
    prefix: str
    path_attributes: BGPPathAttribute
    peer_ip: str
    peer_asn: int
    local_asn: int
    segment: Optional[str] = None
    attachment_id: Optional[str] = None
    route_source: Optional[str] = None  # CloudWAN, TGW, DX, VPN


@dataclass
class BGPPeer:
    """BGP peer information across different attachment types."""
    peer_ip: str
    peer_asn: int
    local_ip: str
    local_asn: int
    attachment_type: str  # TGW_PEERING, VPN, CONNECT, DIRECT_CONNECT
    attachment_id: str
    state: str
    segment: Optional[str] = None
    bgp_attributes: Dict[str, Any] = field(default_factory=dict)


class BGPAnalysisEngine:
    """Comprehensive BGP analysis engine for CloudWAN."""
    
    def __init__(self):
        self.routes: List[BGPRoute] = []
        self.peers: List[BGPPeer] = []
        self.asn_conflicts: List[Tuple[int, List[str]]] = []
        
    def add_route(self, route: BGPRoute) -> None:
        """Add a BGP route for analysis."""
        self.routes.append(route)
        
    def add_peer(self, peer: BGPPeer) -> None:
        """Add a BGP peer for analysis."""
        self.peers.append(peer)
        
    def analyze_as_path_prepending(self, prefix: str = None) -> Dict[str, Any]:
        """Analyze AS path prepending patterns."""
        prepend_analysis = {
            "total_routes_analyzed": 0,
            "routes_with_prepending": 0,
            "prepending_patterns": {},
            "excessive_prepending": [],
            "recommendations": []
        }
        
        routes_to_analyze = self.routes
        if prefix:
            routes_to_analyze = [r for r in self.routes if r.prefix == prefix]
        
        for route in routes_to_analyze:
            prepend_analysis["total_routes_analyzed"] += 1
            as_path = route.path_attributes.as_path
            
            if len(as_path) > 1:
                # Detect AS path prepending (repeated ASNs)
                asn_counts = {}
                for asn in as_path:
                    asn_counts[asn] = asn_counts.get(asn, 0) + 1
                
                for asn, count in asn_counts.items():
                    if count > 1:
                        prepend_analysis["routes_with_prepending"] += 1
                        prepend_key = f"ASN_{asn}"
                        if prepend_key not in prepend_analysis["prepending_patterns"]:
                            prepend_analysis["prepending_patterns"][prepend_key] = []
                        prepend_analysis["prepending_patterns"][prepend_key].append({
                            "prefix": route.prefix,
                            "prepend_count": count - 1,
                            "as_path": as_path
                        })
                        
                        # Flag excessive prepending (>3 repeats)
                        if count > 4:
                            prepend_analysis["excessive_prepending"].append({
                                "prefix": route.prefix,
                                "asn": asn,
                                "prepend_count": count - 1,
                                "risk": "HIGH"
                            })
        
        # Generate recommendations
        if prepend_analysis["excessive_prepending"]:
            prepend_analysis["recommendations"].append("Review excessive AS path prepending for potential routing manipulation")
        
        if prepend_analysis["routes_with_prepending"] > prepend_analysis["total_routes_analyzed"] * 0.5:
            prepend_analysis["recommendations"].append("High percentage of routes use prepending - verify routing policies")
            
        return prepend_analysis
    
    def analyze_med_attributes(self) -> Dict[str, Any]:
        """Analyze Multi-Exit Discriminator usage."""
        med_analysis = {
            "routes_with_med": 0,
            "med_values": {},
            "med_conflicts": [],
            "recommendations": []
        }
        
        for route in self.routes:
            if route.path_attributes.med is not None:
                med_analysis["routes_with_med"] += 1
                med_value = route.path_attributes.med
                
                if med_value not in med_analysis["med_values"]:
                    med_analysis["med_values"][med_value] = []
                med_analysis["med_values"][med_value].append(route.prefix)
        
        # Detect potential MED conflicts (same prefix, different MEDs from same AS)
        prefix_meds = {}
        for route in self.routes:
            if route.path_attributes.med is not None:
                key = f"{route.prefix}_{route.peer_asn}"
                if key not in prefix_meds:
                    prefix_meds[key] = []
                prefix_meds[key].append(route.path_attributes.med)
        
        for key, meds in prefix_meds.items():
            if len(set(meds)) > 1:
                prefix, asn = key.split("_")
                med_analysis["med_conflicts"].append({
                    "prefix": prefix,
                    "peer_asn": int(asn),
                    "med_values": list(set(meds))
                })
        
        if med_analysis["med_conflicts"]:
            med_analysis["recommendations"].append("Resolve MED conflicts for consistent routing behavior")
            
        return med_analysis
    
    def analyze_community_values(self) -> Dict[str, Any]:
        """Analyze BGP community attribute usage."""
        community_analysis = {
            "routes_with_communities": 0,
            "well_known_communities": {},
            "custom_communities": {},
            "security_implications": [],
            "recommendations": []
        }
        
        for route in self.routes:
            if route.path_attributes.communities:
                community_analysis["routes_with_communities"] += 1
                
                for community in route.path_attributes.communities:
                    # Check for well-known communities
                    if community in [BGPCommunity.NO_EXPORT.value, BGPCommunity.NO_ADVERTISE.value, BGPCommunity.NO_EXPORT_SUBCONFED.value]:
                        if community not in community_analysis["well_known_communities"]:
                            community_analysis["well_known_communities"][community] = []
                        community_analysis["well_known_communities"][community].append(route.prefix)
                    else:
                        # Custom community
                        if community not in community_analysis["custom_communities"]:
                            community_analysis["custom_communities"][community] = []
                        community_analysis["custom_communities"][community].append(route.prefix)
        
        # Security implications
        if BGPCommunity.NO_EXPORT.value in community_analysis["well_known_communities"]:
            community_analysis["security_implications"].append("NO_EXPORT community limits route propagation - verify intentional")
        
        return community_analysis
    
    def validate_longest_prefix_match(self, target_ip: str) -> Dict[str, Any]:
        """Validate longest prefix matching for a target IP."""
        try:
            target_addr = ipaddress.ip_address(target_ip)
            matching_routes = []
            
            for route in self.routes:
                try:
                    network = ipaddress.ip_network(route.prefix, strict=False)
                    if target_addr in network:
                        matching_routes.append({
                            "prefix": route.prefix,
                            "prefix_length": network.prefixlen,
                            "next_hop": route.path_attributes.next_hop,
                            "as_path": route.path_attributes.as_path,
                            "peer_asn": route.peer_asn,
                            "local_pref": route.path_attributes.local_pref,
                            "med": route.path_attributes.med
                        })
                except ValueError:
                    continue
            
            # Sort by prefix length (longest first)
            matching_routes.sort(key=lambda x: x["prefix_length"], reverse=True)
            
            return {
                "target_ip": target_ip,
                "matching_routes": matching_routes,
                "longest_match": matching_routes[0] if matching_routes else None,
                "total_matches": len(matching_routes)
            }
            
        except ValueError:
            return {"error": f"Invalid IP address: {target_ip}"}
    
    def detect_asn_conflicts(self) -> Dict[str, Any]:
        """Detect overlapping ASN usage across different contexts."""
        asn_usage = {}
        conflicts = []
        
        # Collect ASN usage from all peers
        for peer in self.peers:
            local_asn = peer.local_asn
            peer_asn = peer.peer_asn
            
            # Track local ASN usage
            if local_asn not in asn_usage:
                asn_usage[local_asn] = {"local_contexts": [], "peer_contexts": []}
            asn_usage[local_asn]["local_contexts"].append({
                "attachment_type": peer.attachment_type,
                "attachment_id": peer.attachment_id,
                "segment": peer.segment
            })
            
            # Track peer ASN usage
            if peer_asn not in asn_usage:
                asn_usage[peer_asn] = {"local_contexts": [], "peer_contexts": []}
            asn_usage[peer_asn]["peer_contexts"].append({
                "attachment_type": peer.attachment_type,
                "attachment_id": peer.attachment_id,
                "segment": peer.segment
            })
        
        # Detect conflicts (same ASN used in multiple contexts)
        for asn, contexts in asn_usage.items():
            local_count = len(contexts["local_contexts"])
            peer_count = len(contexts["peer_contexts"])
            
            if local_count > 1:
                conflicts.append({
                    "asn": asn,
                    "conflict_type": "local_asn_reuse",
                    "contexts": contexts["local_contexts"],
                    "severity": "HIGH"
                })
                
            if peer_count > 1 and len(set(c["attachment_type"] for c in contexts["peer_contexts"])) > 1:
                conflicts.append({
                    "asn": asn,
                    "conflict_type": "peer_asn_multiple_attachment_types",
                    "contexts": contexts["peer_contexts"],
                    "severity": "MEDIUM"
                })
        
        return {
            "total_asns": len(asn_usage),
            "conflicts": conflicts,
            "asn_usage_map": asn_usage
        }
    
    def get_as_paths_for_prefix(self, prefix: str) -> Dict[str, Any]:
        """Get all AS paths for a specific prefix."""
        prefix_routes = [r for r in self.routes if r.prefix == prefix]
        
        if not prefix_routes:
            return {"error": f"No routes found for prefix {prefix}"}
        
        as_path_analysis = {
            "prefix": prefix,
            "total_paths": len(prefix_routes),
            "unique_as_paths": [],
            "path_diversity": {},
            "preferred_path": None,
            "path_attributes_comparison": []
        }
        
        # Collect unique AS paths
        seen_paths = set()
        for route in prefix_routes:
            path_str = " ".join(map(str, route.path_attributes.as_path))
            if path_str not in seen_paths:
                seen_paths.add(path_str)
                as_path_analysis["unique_as_paths"].append({
                    "as_path": route.path_attributes.as_path,
                    "path_length": len(route.path_attributes.as_path),
                    "origin_asn": route.path_attributes.as_path[-1] if route.path_attributes.as_path else None,
                    "peer_asn": route.peer_asn,
                    "local_pref": route.path_attributes.local_pref,
                    "med": route.path_attributes.med,
                    "communities": route.path_attributes.communities
                })
        
        # Analyze path diversity
        path_lengths = [len(r.path_attributes.as_path) for r in prefix_routes]
        as_path_analysis["path_diversity"] = {
            "min_path_length": min(path_lengths) if path_lengths else 0,
            "max_path_length": max(path_lengths) if path_lengths else 0,
            "avg_path_length": sum(path_lengths) / len(path_lengths) if path_lengths else 0
        }
        
        # Determine preferred path using BGP decision process
        if prefix_routes:
            # BGP best path selection (simplified)
            # 1. Highest local preference
            # 2. Shortest AS path
            # 3. Lowest MED
            # 4. Prefer external over internal
            best_route = max(prefix_routes, key=lambda r: (
                r.path_attributes.local_pref or 100,  # Higher is better
                -len(r.path_attributes.as_path),       # Shorter is better (negative for reverse sort)
                -(r.path_attributes.med or 0)         # Lower is better (negative for reverse sort)
            ))
            
            as_path_analysis["preferred_path"] = {
                "as_path": best_route.path_attributes.as_path,
                "peer_asn": best_route.peer_asn,
                "next_hop": best_route.path_attributes.next_hop,
                "local_pref": best_route.path_attributes.local_pref,
                "med": best_route.path_attributes.med,
                "selection_reason": "BGP best path selection algorithm"
            }
        
        # Compare all path attributes
        for route in prefix_routes:
            as_path_analysis["path_attributes_comparison"].append({
                "peer_ip": route.peer_ip,
                "peer_asn": route.peer_asn,
                "as_path": route.path_attributes.as_path,
                "local_pref": route.path_attributes.local_pref,
                "med": route.path_attributes.med,
                "origin": route.path_attributes.origin.value if route.path_attributes.origin else None,
                "communities": route.path_attributes.communities
            })
        
        return as_path_analysis
    
    def validate_routing_policies(self) -> Dict[str, Any]:
        """Comprehensive routing policy validation."""
        policy_analysis = {
            "as_path_prepending": self.analyze_as_path_prepending(),
            "med_analysis": self.analyze_med_attributes(),
            "community_analysis": self.analyze_community_values(),
            "asn_conflicts": self.detect_asn_conflicts(),
            "policy_compliance": self._assess_policy_compliance(),
            "security_risks": self._detect_security_risks()
        }
        
        return policy_analysis
    
    def _assess_policy_compliance(self) -> Dict[str, Any]:
        """Assess compliance with BGP best practices."""
        compliance = {
            "compliant": True,
            "violations": [],
            "warnings": [],
            "score": 100
        }
        
        # Check for required attributes
        routes_missing_origin = [r for r in self.routes if not r.path_attributes.origin]
        if routes_missing_origin:
            compliance["violations"].append(f"{len(routes_missing_origin)} routes missing Origin attribute")
            compliance["score"] -= 10
        
        # Check for proper AS path validation
        for route in self.routes:
            if route.peer_asn not in route.path_attributes.as_path:
                compliance["violations"].append(f"Route {route.prefix}: Peer ASN {route.peer_asn} not in AS path")
                compliance["score"] -= 5
        
        # Check for local preference consistency
        local_prefs = [r.path_attributes.local_pref for r in self.routes if r.path_attributes.local_pref]
        if len(set(local_prefs)) > 10:  # Too many different local preferences
            compliance["warnings"].append("High local preference diversity may indicate inconsistent policy")
        
        compliance["compliant"] = compliance["score"] >= 70
        return compliance
    
    def _detect_security_risks(self) -> List[Dict[str, Any]]:
        """Detect potential security risks in BGP configuration."""
        risks = []
        
        # Check for AS path hijacking potential
        origin_asns = {}
        for route in self.routes:
            if route.path_attributes.as_path:
                origin_asn = route.path_attributes.as_path[-1]
                if origin_asn not in origin_asns:
                    origin_asns[origin_asn] = []
                origin_asns[origin_asn].append(route.prefix)
        
        # Flag ASNs with too many prefixes (potential hijacking)
        for asn, prefixes in origin_asns.items():
            if len(prefixes) > 1000:  # Threshold for suspicious behavior
                risks.append({
                    "risk_type": "AS_HIJACKING_POTENTIAL",
                    "severity": "HIGH",
                    "asn": asn,
                    "prefix_count": len(prefixes),
                    "description": f"ASN {asn} originates {len(prefixes)} prefixes - verify legitimacy"
                })
        
        # Check for suspicious AS paths (too long, suspicious ASNs)
        for route in self.routes:
            as_path = route.path_attributes.as_path
            if len(as_path) > 10:
                risks.append({
                    "risk_type": "SUSPICIOUS_AS_PATH_LENGTH",
                    "severity": "MEDIUM",
                    "prefix": route.prefix,
                    "as_path_length": len(as_path),
                    "as_path": as_path
                })
        
        return risks


def parse_bgp_attributes_from_aws(route_data: Dict[str, Any]) -> BGPPathAttribute:
    """Parse BGP attributes from AWS API response format."""
    attributes = BGPPathAttribute()
    
    # Parse AS path
    if "AsPath" in route_data:
        attributes.as_path = route_data["AsPath"]
    
    # Parse MED
    if "Med" in route_data:
        attributes.med = route_data["Med"]
    
    # Parse Local Preference
    if "LocalPreference" in route_data:
        attributes.local_pref = route_data["LocalPreference"]
    
    # Parse Communities
    if "Community" in route_data:
        attributes.communities = route_data["Community"]
    
    # Parse Next Hop
    if "NextHop" in route_data:
        attributes.next_hop = route_data["NextHop"]
    
    # Parse Origin
    if "Origin" in route_data:
        origin_value = route_data["Origin"].lower()
        if origin_value == "igp":
            attributes.origin = BGPOrigin.IGP
        elif origin_value == "egp":
            attributes.origin = BGPOrigin.EGP
        else:
            attributes.origin = BGPOrigin.INCOMPLETE
    
    # Calculate AS path prepending
    if attributes.as_path:
        asn_counts = {}
        for asn in attributes.as_path:
            asn_counts[asn] = asn_counts.get(asn, 0) + 1
        attributes.as_path_prepend_count = max(asn_counts.values()) - 1 if asn_counts else 0
    
    return attributes