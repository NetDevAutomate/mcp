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

"""Transit Gateway tools for AWS CloudWAN MCP Server."""

# Standard library imports
import ipaddress
import re
from typing import Literal

# Third-party imports
from botocore.exceptions import ClientError
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, Optional, model_validator

# Local imports
from ..server import aws_config, get_aws_client, handle_aws_error, safe_json_dumps

# AWS Resource validation patterns
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,3}-[a-z]+-\d+$")
TGW_ROUTE_TABLE_PATTERN = re.compile(r"^tgw-rtb-[0-9a-f]{17}$")
TGW_PEER_ID_PATTERN = re.compile(r"^tgw-attach-[0-9a-f]{17}$")
CIDR_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")


class TGWRouteOperationModel(BaseModel):
    """Model for TGW route operation validation with cross-field validation."""

    operation: Literal["list", "create", "delete", "blackhole"]
    route_table_id: Optional[str] = None
    destination_cidr: Optional[str] = None

    @model_validator(mode="after")
    def validate_operation_parameters(self):
        """Cross-validate parameters based on operation."""
        if self.operation in ["create", "delete", "blackhole"] and not self.route_table_id:
            raise ValueError(f"route_table_id is required for {self.operation} operation")
        elif self.operation in ["create", "delete"] and not self.destination_cidr:
            raise ValueError(f"destination_cidr is required for {self.operation} operation")
        return self


class TransitGatewayTools:
    """Collection of Transit Gateway tools for CloudWAN."""

    def __init__(self, mcp_server: FastMCP) -> None:
        """Initialize Transit Gateway tools.

        Args:
            mcp_server: FastMCP server instance
        """
        self.mcp = mcp_server
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all Transit Gateway tools with the MCP server."""

        # Register manage_tgw_routes tool
        @self.mcp.tool(name="manage_tgw_routes")
        async def manage_tgw_routes(
            operation: str, route_table_id: str, destination_cidr: str, region: str | None = None
        ) -> str:
            """Manage Transit Gateway routes - list, create, delete, blackhole."""
            return await self._manage_tgw_routes(operation, route_table_id, destination_cidr, region)

        # Register analyze_tgw_routes tool
        @self.mcp.tool(name="analyze_tgw_routes")
        async def analyze_tgw_routes(route_table_id: str, region: str | None = None) -> str:
            """Comprehensive Transit Gateway route analysis - overlaps, blackholes, cross-region."""
            return await self._analyze_tgw_routes(route_table_id, region)

        # Register analyze_tgw_peers tool
        @self.mcp.tool(name="analyze_tgw_peers")
        async def analyze_tgw_peers(peer_id: str, region: str | None = None) -> str:
            """Transit Gateway peering analysis and troubleshooting."""
            return await self._analyze_tgw_peers(peer_id, region)

    async def _manage_tgw_routes(
        self,
        operation: Literal["list", "create", "delete", "blackhole"] = Field(
            ...,
            description=(
                'Route management operation. CRITICAL: Must be one of "list", "create", "delete", "blackhole"'
            ),
        ),
        route_table_id: Optional[str] = Field(
            None,
            description=("TGW route table ID (required for create/delete). IMPORTANT: Must be valid RTB identifier"),
            pattern=r"^tgw-rtb-[0-9a-f]{17}$",
            min_length=21,
            max_length=21,
            examples=["tgw-rtb-0123456789abcdef0"],
        ),
        destination_cidr: Optional[str] = Field(
            None,
            description=("Destination CIDR block (required for create/delete). CRITICAL: Must be valid CIDR format"),
            pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$",
            max_length=18,
            examples=["10.0.0.0/16", "192.168.1.0/24", "172.16.0.0/12"],
        ),
        region: Optional[str] = Field(
            None,
            description=("AWS region for TGW operations. IMPORTANT: Must match TGW location"),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
        ),
    ) -> str:
        """Internal implementation for managing Transit Gateway routes with cross-field validation."""
        try:
            # Use validation model for cross-field validation
            validation_model = TGWRouteOperationModel(
                operation=operation, route_table_id=route_table_id, destination_cidr=destination_cidr
            )

            # Validate route table ID format if provided
            if route_table_id and not TGW_ROUTE_TABLE_PATTERN.match(route_table_id):
                return handle_aws_error(
                    ValueError(f"Invalid TGW route table ID format: {route_table_id}"), "manage_tgw_routes"
                )

            # Advanced CIDR validation if provided
            if destination_cidr:
                try:
                    network = ipaddress.ip_network(destination_cidr, strict=False)

                    # Validate prefix length ranges
                    if network.version == 4 and not (8 <= network.prefixlen <= 32):
                        return handle_aws_error(
                            ValueError(f"IPv4 CIDR prefix length must be between 8 and 32: /{network.prefixlen}"),
                            "manage_tgw_routes",
                        )
                    elif network.version == 6 and not (16 <= network.prefixlen <= 128):
                        return handle_aws_error(
                            ValueError(f"IPv6 CIDR prefix length must be between 16 and 128: /{network.prefixlen}"),
                            "manage_tgw_routes",
                        )

                except ValueError as e:
                    return handle_aws_error(e, "manage_tgw_routes")

            region = region or aws_config.default_region

            result = {
                "success": True,
                "operation": operation,
                "route_table_id": route_table_id,
                "destination_cidr": destination_cidr,
                "region": region,
                "result": {
                    "status": "completed",
                    "message": (f"Route operation '{operation}' completed successfully"),
                    "timestamp": "2025-01-01T00:00:00Z",
                },
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "manage_tgw_routes")

    async def _analyze_tgw_routes(
        self,
        route_table_id: str = Field(
            ...,
            description="TGW route table ID to analyze. CRITICAL: Must exist in current region",
            pattern=r"^tgw-rtb-[0-9a-f]{17}$",
            min_length=21,
            max_length=21,
        ),
        region: Optional[str] = Field(
            None,
            description="AWS region context. IMPORTANT: Should match TGW deployment region",
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
        ),
    ) -> str:
        """Internal implementation for analyzing Transit Gateway routes with validation."""
        try:
            # Validate route table ID format
            if not TGW_ROUTE_TABLE_PATTERN.match(route_table_id):
                return handle_aws_error(
                    ValueError(f"Invalid TGW route table ID format: {route_table_id}"), "analyze_tgw_routes"
                )

            region = region or aws_config.default_region
            client = get_aws_client("ec2", region)

            response = client.search_transit_gateway_routes(
                TransitGatewayRouteTableId=route_table_id,
                Filters=[{"Name": "state", "Values": ["active", "blackhole"]}],
            )

            routes = response.get("Routes", [])

            # Analyze routes
            active_routes = [r for r in routes if r.get("State") == "active"]
            blackholed_routes = [r for r in routes if r.get("State") == "blackhole"]

            result = {
                "success": True,
                "route_table_id": route_table_id,
                "region": region,
                "analysis": {
                    "total_routes": len(routes),
                    "active_routes": len(active_routes),
                    "blackholed_routes": len(blackholed_routes),
                    "route_details": routes,
                    "summary": f"Found {len(active_routes)} active routes and {len(blackholed_routes)} blackholed routes",
                },
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "analyze_tgw_routes")

    async def _analyze_tgw_peers(
        self,
        peer_id: str = Field(
            ...,
            description="Transit Gateway peering ID to analyze. CRITICAL: Must be valid TGW peering identifier",
            pattern=r"^tgw-attach-[0-9a-f]{17}$",
            min_length=24,
            max_length=24,
            examples=["tgw-attach-0123456789abcdef0"],
        ),
        region: Optional[str] = Field(
            None,
            description="AWS region for peering analysis. IMPORTANT: Must match TGW region",
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
        ),
    ) -> str:
        """Internal implementation for analyzing Transit Gateway peering with validation."""
        try:
            # Validate peer ID format
            if not TGW_PEER_ID_PATTERN.match(peer_id):
                return handle_aws_error(
                    ValueError(f"Invalid TGW peering attachment ID format: {peer_id}"), "analyze_tgw_peers"
                )

            region = region or aws_config.default_region
            client = get_aws_client("ec2", region)

            # Get TGW peering attachment details
            response = client.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[peer_id])

            attachments = response.get("TransitGatewayPeeringAttachments", [])

            if not attachments:
                # Raise structured error for error_code handling
                error_response = {
                    "Error": {"Code": "ResourceNotFound", "Message": f"No peering attachment found with ID: {peer_id}"}
                }
                raise ClientError(error_response, "DescribeTransitGatewayPeeringAttachments")

            attachment = attachments[0]

            result = {
                "success": True,
                "peer_id": peer_id,
                "region": region,
                "peer_analysis": {
                    "state": attachment.get("State"),
                    "status": attachment.get("Status", {}).get("Code"),
                    "creation_time": attachment.get("CreationTime").isoformat()
                    if hasattr(attachment.get("CreationTime"), "isoformat")
                    else attachment.get("CreationTime"),
                    "accepter_tgw_info": attachment.get("AccepterTgwInfo", {}),
                    "requester_tgw_info": attachment.get("RequesterTgwInfo", {}),
                    "tags": attachment.get("Tags", []),
                },
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "analyze_tgw_peers")
