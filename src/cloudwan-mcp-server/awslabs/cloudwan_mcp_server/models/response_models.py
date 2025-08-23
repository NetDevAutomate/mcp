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

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ResponseStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"


class HttpStatusCode(Enum):
    OK = 200
    BAD_REQUEST = 400
    INTERNAL_SERVER_ERROR = 500


class BaseResponse(BaseModel):
    status: str = Field(..., description="Response status (success/error)")
    timestamp: datetime = Field(default_factory=datetime.now, description="Response generation time")


class ErrorResponse(BaseResponse):
    error: Dict[str, Any] = Field(..., description="Error details")
    http_status: HttpStatusCode = Field(HttpStatusCode.INTERNAL_SERVER_ERROR, description="HTTP status code")


class VpcDiscoveryResponse(BaseResponse):
    """Response model for VPC discovery operations."""

    vpcs: List[Dict[str, Any]] = Field(..., description="List of discovered VPCs with details")
    region: str = Field(..., description="AWS region analyzed")


class CoreNetworkPolicyResponse(BaseResponse):
    """Response model for core network policy retrieval."""

    core_network_id: str = Field(..., description="CloudWAN Core Network ID analyzed")
    policy_document: Dict[str, Any] = Field(..., description="Policy document structure")


class NetworkPathResponse(BaseResponse):
    """Response model for network path analysis."""

    path_trace: List[Dict[str, Any]] = Field(..., description="Hop-by-hop path analysis")
    total_hops: int = Field(..., description="Total hops in path")


class SecurityAnalysisResponse(BaseResponse):
    """Response model for security analysis tools."""

    security_score: Optional[float] = Field(
        None, description="Security posture score (0.0-10.0 scale)", ge=0.0, le=10.0
    )
    findings: List[Dict[str, Any]] = Field(default=[], description="List of security findings")


class FirewallPolicyResponse(BaseResponse):
    """Response model for Network Firewall policy analysis."""

    firewall_arn: str = Field(..., description="ARN of analyzed firewall")
    rule_groups: List[Dict[str, Any]] = Field(..., description="Parsed rule group analysis")


# Update __init__.py exports
def export_models():
    pass
