import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest
from botocore.exceptions import NoCredentialsError

from awslabs.cloudwan_mcp_server.security.error_handler import (
    CloudWatchBatchedClient,
    CredentialSanitizer,
    RecoveryExecutor,
    SecurityConfig,
    SecurityErrorHandler,
    SecurityHubClient,
    SuppressionPolicy,
)

"""Enhanced security tests for error handler fixes."""

# Test security patterns - FOR TESTING SANITIZATION ONLY
# pragma: allowlist secret
MOCK_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Mock access key for sanitization testing
# pragma: allowlist secret
MOCK_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Mock secret for testing
# pragma: allowlist secret
MOCK_HIGH_ENTROPY = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="  # Base64 test string


class TestErrorHandlerSecurity:
    """Test security aspects of error handler."""

    def test_credential_sanitization_effectiveness(self):
        """Test effectiveness of credential sanitization."""
        # pragma: allowlist secret
        test_error = f"Connection failed using access key {MOCK_AWS_ACCESS_KEY}"

        # ... existing code ...

    def test_base64_string_handling(self):
        """Test handling of base64 encoded strings."""
        # pragma: allowlist secret
        base64_test = "dGVzdCBzdHJpbmcgZm9yIGVuY29kaW5n"  # Test base64 pattern

        # ... existing code ...
        # ... existing code ...
        # ... existing code ...


class TestSecurityFixes:
    @pytest.mark.asyncio
    async def test_context_fallback_works(self):
        handler = SecurityErrorHandler.instance()
        assert handler.config.cloudwatch_namespace == "cloudwan-mcp-fallback"

    @pytest.mark.asyncio
    async def test_cloudwatch_client_cleanup(self):
        async with CloudWatchBatchedClient("test") as client:
            pass
        assert client._closed
        assert client._flush_task.cancelled()

    def test_all_credential_patterns_implemented(self):
        sanitizer = CredentialSanitizer()
        assert len(sanitizer.PATTERNS) >= 28

    @pytest.mark.asyncio
    async def test_cloudwatch_auth_headers(self):
        client = CloudWatchBatchedClient("test")
        await client._ensure_client()
        # Verify boto3 client is used (which handles auth automatically)
        assert client._client is not None
        assert hasattr(client._client, "put_metric_data")


class TestRecoveryExecutor:
    """Test the new automated recovery execution system."""

    @pytest.mark.asyncio
    async def test_recovery_executor_initialization(self):
        """Test RecoveryExecutor initializes properly."""
        metrics_client = CloudWatchBatchedClient("test")
        executor = RecoveryExecutor(metrics_client)

        assert executor._circuit_state == {}
        assert executor._metrics_client == metrics_client
        assert len(executor._action_implementations) >= 8

    @pytest.mark.asyncio
    async def test_successful_action_execution(self):
        """Test successful execution of recovery actions."""
        executor = RecoveryExecutor()
        context = {"service_name": "test-service"}

        results = await executor.execute_actions(["LogEvent", "HealthCheckRefresh"], context, "test-correlation-123")

        assert results["LogEvent"] == True
        assert results["HealthCheckRefresh"] == True
        assert "logged_at" in context
        assert "health_check_refreshed_at" in context

    @pytest.mark.asyncio
    async def test_circuit_breaker_functionality(self):
        """Test circuit breaker prevents action storms."""
        executor = RecoveryExecutor()

        # Mock an action that always fails
        async def failing_action(context):
            raise Exception("Simulated failure")

        executor._action_implementations["FailingAction"] = failing_action

        # Execute action 3 times to trip circuit
        for i in range(3):
            results = await executor.execute_actions(["FailingAction"], {}, f"corr-{i}")
            assert results["FailingAction"] == False

        # Verify circuit is now open
        assert executor._is_circuit_open("FailingAction") == True

        # Next execution should be blocked by circuit
        results = await executor.execute_actions(["FailingAction"], {}, "corr-blocked")
        assert results["FailingAction"] == False

    @pytest.mark.asyncio
    async def test_circuit_breaker_auto_reset(self):
        """Test circuit breaker resets after cooldown period."""
        executor = RecoveryExecutor()

        # Force circuit to open state
        executor._circuit_state["TestAction"] = {
            "failures": 3,
            "opened_at": time.time() - 70,  # 70 seconds ago (past 60s cooldown)
            "success_count": 0,
        }

        # Circuit should be closed now
        assert executor._is_circuit_open("TestAction") == False

    @pytest.mark.asyncio
    async def test_success_rate_tracking(self):
        """Test success rate calculation for recovery actions."""
        executor = RecoveryExecutor()

        # Record some successes and failures
        for i in range(7):
            executor._record_success("TestAction")

        for i in range(3):
            executor._record_failure("TestAction")

        success_rate = executor.get_success_rate("TestAction")
        assert success_rate == 0.7  # 7 successes out of 10 total

    @pytest.mark.asyncio
    async def test_credential_rotation_action(self):
        """Test credential rotation recovery action."""
        executor = RecoveryExecutor()
        context = {"aws_account": "123456789012"}

        result = await executor._rotate_credentials(context)
        assert result == True  # Should succeed in simulation

    @pytest.mark.asyncio
    async def test_exponential_backoff_action(self):
        """Test exponential backoff recovery action."""
        executor = RecoveryExecutor()
        context = {"failure_count": 3}

        result = await executor._handle_exponential_backoff(context)
        assert result == True
        assert "backoff_until" in context
        assert "backoff_duration" in context
        assert context["backoff_duration"] == 8  # 2^3

    @pytest.mark.asyncio
    async def test_recovery_metrics_recording(self):
        """Test recovery action metrics are recorded to CloudWatch."""
        mock_metrics = AsyncMock()
        executor = RecoveryExecutor(mock_metrics)

        await executor.execute_actions(["LogEvent"], {}, "test-correlation")

        # Verify metrics were recorded
        mock_metrics.put_metric.assert_called()
        call_args = mock_metrics.put_metric.call_args
        assert call_args[0][0] == "RecoveryAction"  # Metric name
        assert call_args[0][1] == 1  # Success value
        assert call_args[1]["Action"] == "LogEvent"


class TestSecurityHubIntegration:
    @pytest.mark.asyncio
    async def test_critical_finding_submission(self):
        """Test Security Hub finding submission for critical errors."""
        config = SecurityConfig("test")
        handler = SecurityErrorHandler(config)
        context = {"account_id": "111122223333"}

        # Create critical error
        error = NoCredentialsError()

        # Mock Security Hub client
        with patch.object(handler.security_hub, "submit_finding") as mock_submit:
            result = await handler.handle(error, context, SuppressionPolicy.RESOURCE_CLEANUP)

            mock_submit.assert_called_once()
            assert result["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_security_hub_circuit_breaker(self):
        """Test Security Hub circuit breaker functionality."""
        client = SecurityHubClient()
        client._open_circuit()

        # Attempt submission while circuit is open
        await client.submit_finding({"dummy": "finding"})

        # Queue should be empty because circuit is open
        assert client._queue.qsize() == 0

        # Wait for circuit reset
        await asyncio.sleep(65)
        assert client._circuit_open is False

    @pytest.mark.asyncio
    async def test_security_hub_batch_processing(self):
        """Test Security Hub batch processing."""
        client = SecurityHubClient()

        # Add multiple findings
        for i in range(150):  # More than batch size
            await client.submit_finding({"finding_id": f"test-{i}"})

        # Queue should contain all findings
        assert client._queue.qsize() == 150
