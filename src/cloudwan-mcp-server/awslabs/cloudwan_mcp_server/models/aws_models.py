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

"""AWS resource models for CloudWAN MCP Server."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VPCResource(BaseModel):
    """VPC resource model."""

    vpc_id: str = Field(..., description="VPC identifier")
    region: str = Field(..., description="AWS region")
    cidr_block: str = Field(..., description="Primary CIDR block")
    state: str = Field(..., description="VPC state")
    is_default: bool = Field(False, description="Whether this is the default VPC")
    tags: List[Dict[str, str]] = Field(default_factory=list, description="VPC tags")


class GlobalNetwork(BaseModel):
    """Global Network resource model."""

    global_network_id: str = Field(..., description="Global Network ID")
    global_network_arn: str = Field(..., description="Global Network ARN")
    description: Optional[str] = Field(None, description="Network description")
    state: str = Field(..., description="Network state")
    created_at: str = Field(..., description="Creation timestamp")
    tags: List[Dict[str, str]] = Field(default_factory=list, description="Network tags")


class CoreNetwork(BaseModel):
    """Core Network resource model."""

    core_network_id: str = Field(..., description="Core Network ID")
    core_network_arn: str = Field(..., description="Core Network ARN")
    global_network_id: str = Field(..., description="Associated Global Network ID")
    state: str = Field(..., description="Core Network state")
    description: Optional[str] = Field(None, description="Network description")
    created_at: str = Field(..., description="Creation timestamp")
    tags: List[Dict[str, str]] = Field(default_factory=list, description="Network tags")


class CoreNetworkPolicy(BaseModel):
    """Core Network Policy model."""

    policy_version_id: str = Field(..., description="Policy version ID")
    policy_document: Dict[str, Any] = Field(..., description="Policy document")
    alias: str = Field(..., description="Policy alias (LIVE/LATEST)")
    description: Optional[str] = Field(None, description="Policy description")
    created_at: str = Field(..., description="Creation timestamp")
