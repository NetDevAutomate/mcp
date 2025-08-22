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

"""Tool configuration management for CloudWAN MCP server."""

from typing import Any

from pydantic import BaseModel


class ToolConfiguration(BaseModel):
    """Configuration for individual tools."""

    enabled: bool = True
    timeout_seconds: int = 30
    max_retries: int = 3
    rate_limit: int = 1000
    health_interval: int = 60
    circuit_threshold: int = 5
    priority: int = 100
    services: list[str] = []
    custom_config: dict[str, Any] = {}


class ToolConfigManager:
    """Manager for tool configurations."""

    def __init__(self):
        """Initialize the tool configuration manager."""
        self._configs: dict[str, ToolConfiguration] = {}

    def get_config(self, tool_name: str) -> ToolConfiguration:
        """Get configuration for a specific tool."""
        return self._configs.get(tool_name, ToolConfiguration())

    def update_config(self, tool_name: str, **kwargs) -> None:
        """Update configuration for a specific tool."""
        if tool_name not in self._configs:
            self._configs[tool_name] = ToolConfiguration()
        self._configs[tool_name] = self._configs[tool_name].model_copy(update=kwargs)
