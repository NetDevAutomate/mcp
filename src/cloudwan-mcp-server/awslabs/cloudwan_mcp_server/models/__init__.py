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

"""Models package for CloudWAN MCP Server."""

# Core models - Explicit imports for F403/F405 compliance
from .aws_models import (
    CoreNetwork,
    CoreNetworkPolicy,
    GlobalNetwork,
    VPCResource,
)
from .network_models import (
    CIDRValidation,
    IPDetails,
    NetworkFunctionGroup,
    NetworkPath,
    SegmentRouteAnalysis,
)

# Response models
try:
    from .response_models import (
        BaseResponse,
        CoreNetworkPolicyResponse,
        ErrorResponse,
        FirewallPolicyResponse,
        NetworkPathResponse,
        SecurityAnalysisResponse,
        VpcDiscoveryResponse,
    )
except ImportError:
    # Fallback if response_models not fully implemented
    BaseResponse = dict
    ErrorResponse = dict
    VpcDiscoveryResponse = dict
    CoreNetworkPolicyResponse = dict
    NetworkPathResponse = dict
    SecurityAnalysisResponse = dict
    FirewallPolicyResponse = dict

__all__ = [
    # Core models
    "GlobalNetwork",
    "VPCResource",
    "CoreNetwork",
    "CoreNetworkPolicy",
    "NetworkPath",
    "IPDetails",
    "CIDRValidation",
    "NetworkFunctionGroup",
    "SegmentRouteAnalysis",
    "NetworkFirewall",
    "FirewallPolicy",
    "SuricataRule",
    "FlowLog",
    "FiveTupleFlow",
    "PolicySimulation",
    # Response models
    "BaseResponse",
    "ErrorResponse",
    "VpcDiscoveryResponse",
    "CoreNetworkPolicyResponse",
    "NetworkPathResponse",
    "SecurityAnalysisResponse",
    "FirewallPolicyResponse",
]
