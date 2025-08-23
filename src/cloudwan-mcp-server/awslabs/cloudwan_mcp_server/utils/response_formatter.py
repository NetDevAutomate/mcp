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

"""Response formatting utilities for AWS CloudWAN MCP Server."""

import json
from datetime import datetime
from typing import Any, Dict, Optional


def format_success_response(data: Any, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Format successful response with consistent structure."""
    response = {
        "status": "success",
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
    }

    if metadata:
        response["metadata"] = metadata

    return response


def format_error_response(
    error_message: str, error_code: str = "GeneralError", http_status: int = 500
) -> Dict[str, Any]:
    """Format error response with consistent structure."""
    return {
        "status": "error",
        "error": {"message": error_message, "code": error_code},
        "http_status": http_status,
        "timestamp": datetime.utcnow().isoformat(),
    }


def format_response(success: bool, data: Any = None, error: str = None, **kwargs) -> str:
    """General response formatter that returns JSON string."""
    if success:
        response = format_success_response(data, kwargs.get("metadata"))
    else:
        response = format_error_response(error or "Unknown error", kwargs.get("error_code", "GeneralError"))

    return json.dumps(response, indent=2)
