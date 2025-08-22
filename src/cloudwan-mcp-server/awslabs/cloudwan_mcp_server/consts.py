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

"""Constants for the CloudWAN MCP Server."""

from typing import Final

# Default configuration values
DEFAULT_WIDTH: Final[int] = 1024
DEFAULT_HEIGHT: Final[int] = 1024
DEFAULT_QUALITY: Final[str] = "standard"
DEFAULT_CFG_SCALE: Final[float] = 6.5
DEFAULT_NUMBER_OF_IMAGES: Final[int] = 1

# Default AWS Region
DEFAULT_AWS_REGION: Final[str] = "us-east-1"

# Default Log Level
DEFAULT_LOG_LEVEL: Final[str] = "WARNING"

# Default Operation Mode
DEFAULT_OPERATION_MODE: Final[str] = "simple"

# Cache Configuration
CACHE_MAX_SIZE: Final[int] = 128

# MCP Server Description
MCP_SERVER_DESCRIPTION: Final[str] = (
    "AWS CloudWAN MCP Server - Advanced network analysis and "
    "troubleshooting tools for AWS CloudWAN, Transit Gateway, "
    "Network Firewall, and VPC networking."
)
