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

"""Resource discovery tools for AWS CloudWAN MCP Server."""

# Standard library imports
import re

# Third-party imports
from botocore.exceptions import ClientError, EndpointConnectionError
from mcp.server.fastmcp import FastMCP
from pydantic import Field, Optional

# Local imports
from ..models.aws_models import GlobalNetwork, VPCResource
from ..models.response_models import ErrorResponse, VpcDiscoveryResponse
from ..server import aws_config, get_aws_client, safe_json_dumps

# AWS validation patterns
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,3}-[a-z]+-\d+$")


def handle_aws_error(e: Exception, operation: str) -> str:
    status_code = 500
    if hasattr(e, "response"):
        status_code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 500)
    return ErrorResponse(error={"message": str(e), "operation": operation}, http_status=status_code).json()


class DiscoveryTools:
    """Collection of AWS resource discovery tools for CloudWAN."""

    def __init__(self, mcp_server: FastMCP) -> None:
        """Initialize discovery tools.

        Args:
            mcp_server: FastMCP server instance
        """
        self.mcp = mcp_server
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all discovery tools with the MCP server."""

        # Register discover_vpcs tool
        @self.mcp.tool(name="discover_vpcs")
        async def discover_vpcs(region: str | None = None) -> str:
            """Discover VPCs."""
            return await self._discover_vpcs(region)

        # Register get_global_networks tool
        @self.mcp.tool(name="get_global_networks")
        async def get_global_networks(region: str | None = None) -> str:
            """Discover global networks."""
            return await self._get_global_networks(region)

    async def _discover_vpcs(
        self,
        region: Optional[str] = Field(
            None,
            description=(
                "AWS region to search for VPCs. CRITICAL: Must be valid "
                "AWS region code. Defaults to server configuration"
            ),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
            examples=["us-east-1", "eu-west-1", "ap-southeast-1"],
        ),
    ) -> str:
        """Internal implementation for VPC discovery."""
        # Validate region format if provided
        if region and not AWS_REGION_PATTERN.match(region):
            return handle_aws_error(
                ValueError(f"Invalid AWS region format: {region}. Must match pattern like 'us-east-1'"),
                "discover_vpcs",
            )

        try:
            region = region or aws_config.default_region
            client = get_aws_client("ec2", region)

            response = client.describe_vpcs()
            vpcs = response.get("Vpcs", [])

            # Process VPCs using Pydantic models for validation
            vpc_resources = []
            for vpc in vpcs:
                try:
                    vpc_resource = VPCResource(
                        vpc_id=vpc.get("VpcId"),
                        region=region,
                        cidr_block=vpc.get("CidrBlock"),
                        state=vpc.get("State"),
                        is_default=vpc.get("IsDefault", False),
                        tags=vpc.get("Tags", []),
                    )
                    vpc_resources.append(vpc_resource.dict())
                except Exception:
                    # If validation fails, use original VPC data
                    vpc_resources.append(vpc)

            result = {"success": True, "region": region, "total_count": len(vpc_resources), "vpcs": vpc_resources}

            return VpcDiscoveryResponse(
                status="success", data={"vpcs": vpc_resources, "region": region}, metadata={"analysis_type": "VPC_SCAN"}
            ).json()

        except (ClientError, EndpointConnectionError) as e:
            return handle_aws_error(e, "discover_vpcs")
        except ValueError as ve:
            return handle_aws_error(ve, "discover_vpcs")
        except Exception as e:
            return handle_aws_error(e, "discover_vpcs")

    async def _get_global_networks(
        self,
        region: Optional[str] = Field(
            None,
            description=("AWS region to search for global networks. IMPORTANT: Must match CloudWAN deployment region"),
            pattern=r"^[a-z]{2,3}-[a-z]+-\d+$",
            max_length=20,
            examples=["us-east-1", "eu-west-1", "ap-southeast-1"],
        ),
    ) -> str:
        """Internal implementation for global network discovery."""
        # Validate region format if provided
        if region and not AWS_REGION_PATTERN.match(region):
            return handle_aws_error(
                ValueError(f"Invalid AWS region format: {region}. Must match pattern like 'us-east-1'"),
                "get_global_networks",
            )

        try:
            region = region or aws_config.default_region
            client = get_aws_client("networkmanager", region)

            response = client.describe_global_networks()
            global_networks = response.get("GlobalNetworks", [])

            # Process global networks using Pydantic models
            global_network_resources = []
            for gn in global_networks:
                try:
                    global_network = GlobalNetwork(
                        global_network_id=gn.get("GlobalNetworkId"),
                        global_network_arn=gn.get("GlobalNetworkArn"),
                        description=gn.get("Description"),
                        state=gn.get("State"),
                        created_at=gn.get("CreatedAt").isoformat()
                        if hasattr(gn.get("CreatedAt"), "isoformat")
                        else gn.get("CreatedAt"),
                        tags=gn.get("Tags", []),
                    )
                    global_network_resources.append(global_network.dict())
                except Exception:
                    # If validation fails, use original data
                    global_network_resources.append(gn)

            result = {
                "success": True,
                "region": region,
                "total_count": len(global_network_resources),
                "global_networks": global_network_resources,
            }

            return safe_json_dumps(result, indent=2)

        except Exception as e:
            return handle_aws_error(e, "get_global_networks")
