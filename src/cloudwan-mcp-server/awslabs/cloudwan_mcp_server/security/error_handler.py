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

"""Enterprise security error handler for AWS CloudWAN MCP Server."""

import uuid
from datetime import datetime
from typing import Any, Dict

from ..consts import sanitize_error_message
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SecurityErrorHandler:
    """Enterprise-grade security error handler with ULID correlation."""

    def __init__(self):
        """Initialize security error handler."""
        self.correlation_id = str(uuid.uuid4())

    def handle_security_error(self, error: Exception, operation: str) -> Dict[str, Any]:
        """Handle security-related errors with proper sanitization."""
        try:
            sanitized_message = sanitize_error_message(str(error))

            error_response = {
                "status": "error",
                "error": {
                    "message": sanitized_message,
                    "operation": operation,
                    "correlation_id": self.correlation_id,
                    "timestamp": datetime.utcnow().isoformat(),
                },
                "http_status": 500,
            }

            logger.error(f"Security error in {operation}: {sanitized_message}")
            return error_response

        except Exception as e:
            logger.critical(f"Failed to handle security error: {str(e)}")
            return {"status": "error", "error": {"message": "Internal security error"}, "http_status": 500}
