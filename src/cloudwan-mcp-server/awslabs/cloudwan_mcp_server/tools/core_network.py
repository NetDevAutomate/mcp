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

"""Core Network management tools for AWS CloudWAN MCP Server."""

# Standard library imports
import re
from typing import Literal

# Third-party imports
from mcp.server.fastmcp import FastMCP
from pydantic import Field, Optional

# Local imports
from ..server import aws_config, get_aws_client, handle_aws_error, safe_json_dumps

# Optional imports with fallbacks
try:
    from ..models.response_models import CoreNetworkPolicyResponse
except ImportError:
    # Fallback for response model
    CoreNetworkPolicyResponse = None

# AWS Resource validation patterns
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,3}-[a-z]+-\d+$")
CORE_NETWORK_ID_PATTERN = re.compile(r"^core-network-[0-9a-f]{17}$")
POLICY_VERSION_PATTERN = re.compile(r"^\d+$")


class CoreNetworkTools:
    """Collection of core network management tools for CloudWAN."""

    def __init__(self, mcp_server: FastMCP) -> None:
        """Initialize core network tools.

        Args:
            mcp_server: FastMCP server instance
        """
        self.mcp = mcp_server
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all core network tools with the MCP server."""

        # Register list_core_networks tool
        @self.mcp.tool(name="list_core_networks")
        async def list_core_networks(region: str | None = None) -> str:
            """List CloudWAN core networks."""
            return await self._list_core_networks(region)

        # Register get_core_network_policy tool
        @self.mcp.tool(name="get_core_network_policy")
        async def get_core_network_policy(core_network_id: str, alias: str = "LIVE") -> str:
            """Retrieve the policy document for a CloudWAN Core Network."""
            return await self._get_core_network_policy(core_network_id, alias)

        # Register get_core_network_change_set tool
        @self.mcp.tool(name="get_core_network_change_set")
        async def get_core_network_change_set(core_network_id: str, policy_version_id: str) -> str:
            """Retrieve policy change sets for a CloudWAN Core Network."""
            return await self._get_core_network_change_set(core_network_id, policy_version_id)

        # Register get_core_network_change_events tool
        @self.mcp.tool(name="get_core_network_change_events")
        async def get_core_network_change_events(core_network_id: str, policy_version_id: str) -> str:
            """Retrieve change events for a CloudWAN Core Network."""
            return await self._get_core_network_change_events(core_network_id, policy_version_id)

    async def _list_core_networks(
        self,
        region: Optional[str] = Field(
            None,
            description=(
                "AWS region to search. IMPORTANT: Must be valid AWS region code. Defaults to server configuration"
            ),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
            examples=["us-east-1", "eu-west-1", "ap-southeast-1"],
        ),
    ) -> str:
        """Internal implementation for listing core networks with validation."""
        try:
            # Validate region format if provided
            if region and not AWS_REGION_PATTERN.match(region):
                return handle_aws_error(
                    ValueError(f"Invalid AWS region format: {region}. Must match pattern like 'us-east-1'"),
                    "list_core_networks",
                )

            region = region or aws_config.default_region
            client = get_aws_client("networkmanager", region)

            response = client.list_core_networks()
            core_networks = response.get("CoreNetworks", [])

            if not core_networks:
                return safe_json_dumps(
                    {
                        "success": True,
                        "region": region,
                        "message": ("No CloudWAN core networks found in the specified region."),
                        "core_networks": [],
                    },
                    indent=2,
                )

            result = {
                "success": True,
                "region": region,
                "total_count": len(core_networks),
                "core_networks": core_networks,
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "list_core_networks")

    async def _get_core_network_policy(
        self,
        core_network_id: str = Field(
            ...,
            description=(
                "Core network ID to retrieve policy for. CRITICAL: Must be valid UUID from resource://corenetworks"
            ),
            pattern=r"^core-network-[0-9a-f]{17}$",
            min_length=30,
            max_length=30,
            examples=["core-network-0123456789abcdef0"],
        ),
        alias: Literal["LIVE", "STAGED"] = Field(
            "LIVE",
            description=("Policy version alias (LIVE/STAGED). IMPORTANT: Use valid alias from CloudWAN API"),
        ),
    ) -> str:
        """Internal implementation for retrieving core network policy with validation."""
        try:
            # Validate core network ID format
            if not CORE_NETWORK_ID_PATTERN.match(core_network_id):
                return handle_aws_error(
                    ValueError(f"Invalid core network ID format: {core_network_id}"), "get_core_network_policy"
                )
            client = get_aws_client("networkmanager")  # Region already handled in get_aws_client

            response = client.get_core_network_policy(CoreNetworkId=core_network_id, Alias=alias)

            policy = response.get("CoreNetworkPolicy", {})

            result = {
                "success": True,
                "core_network_id": core_network_id,
                "alias": alias,
                "policy_version_id": policy.get("PolicyVersionId"),
                "policy_document": policy.get("PolicyDocument"),
                "description": policy.get("Description"),
                "created_at": policy.get("CreatedAt").isoformat()
                if hasattr(policy.get("CreatedAt"), "isoformat")
                else policy.get("CreatedAt"),
            }

            if CoreNetworkPolicyResponse:
                return CoreNetworkPolicyResponse(status="success", data=result, metadata={"policy_alias": alias}).json()
            else:
                return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "get_core_network_policy")

    async def _get_core_network_change_set(
        self,
        core_network_id: str = Field(
            ...,
            description="Core network ID to analyze. CRITICAL: Must match core_networks resource IDs",
            pattern=r"^core-network-[0-9a-f]{17}$",
            min_length=30,
            max_length=30,
        ),
        policy_version_id: str = Field(
            ...,
            description="Policy version ID to compare against. IMPORTANT: Must be valid version string from CloudWAN",
            pattern=r"^\d+$",
            min_length=1,
            max_length=10,
        ),
    ) -> str:
        """Internal implementation for retrieving core network change set with validation."""
        try:
            # Validate core network ID and policy version formats
            if not CORE_NETWORK_ID_PATTERN.match(core_network_id):
                return handle_aws_error(
                    ValueError(f"Invalid core network ID format: {core_network_id}"), "get_core_network_change_set"
                )

            if not POLICY_VERSION_PATTERN.match(policy_version_id):
                return handle_aws_error(
                    ValueError(f"Invalid policy version ID format: {policy_version_id}"), "get_core_network_change_set"
                )
            client = get_aws_client("networkmanager")  # Region already handled

            response = client.get_core_network_change_set(
                CoreNetworkId=core_network_id, PolicyVersionId=policy_version_id
            )

            result = {
                "success": True,
                "core_network_id": core_network_id,
                "policy_version_id": policy_version_id,
                "change_sets": response.get("CoreNetworkChanges", []),
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "get_core_network_change_set")

    async def _get_core_network_change_events(
        self,
        core_network_id: str = Field(
            ...,
            description="Core network ID to monitor. CRITICAL: Must be valid core network identifier",
            pattern=r"^core-network-[0-9a-f]{17}$",
            min_length=30,
            max_length=30,
        ),
        policy_version_id: str = Field(
            ...,
            description="Policy version to track changes for. IMPORTANT: Must be active policy version",
            pattern=r"^\d+$",
            min_length=1,
            max_length=10,
        ),
    ) -> str:
        """Internal implementation for retrieving core network change events with validation."""
        try:
            # Cross-validate parameters
            if not CORE_NETWORK_ID_PATTERN.match(core_network_id):
                return handle_aws_error(
                    ValueError(f"Invalid core network ID format: {core_network_id}"), "get_core_network_change_events"
                )

            if not POLICY_VERSION_PATTERN.match(policy_version_id):
                return handle_aws_error(
                    ValueError(f"Invalid policy version ID format: {policy_version_id}"),
                    "get_core_network_change_events",
                )
            client = get_aws_client("networkmanager")  # Region already handled

            response = client.get_core_network_change_events(
                CoreNetworkId=core_network_id, PolicyVersionId=policy_version_id
            )

            result = {
                "success": True,
                "core_network_id": core_network_id,
                "policy_version_id": policy_version_id,
                "change_events": response.get("CoreNetworkChangeEvents", []),
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "get_core_network_change_events")
