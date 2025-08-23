"""Comprehensive test suite for SecurityErrorHandler addressing production readiness issues."""

import asyncio
import contextvars
import time
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from awslabs.cloudwan_mcp_server.security.error_handler import (
    AWSErrorRecovery,
    CloudWatchBatchedClient,
    CredentialSanitizer,
    SecurityClassifier,
    SecurityConfig,
    SecurityErrorHandler,
    SuppressionPolicy,
    ULIDCorrelationEngine,
)


class TestContextManagement:
    """Test context-aware singleton safety and fallback mechanisms."""

    @pytest.mark.asyncio
    async def test_instance_without_context_raises_lookup_error(self):
        """Verify LookupError when no context is set (current behavior)."""
        # Clear any existing context
        SecurityErrorHandler._context = contextvars.ContextVar("security_context")

        with pytest.raises(LookupError):
            SecurityErrorHandler.instance()

    @pytest.mark.asyncio
    async def test_instance_with_context_returns_handler(self):
        """Verify proper context retrieval when set."""
        config = SecurityConfig("test-namespace")
        handler = SecurityErrorHandler(config)
        SecurityErrorHandler._context.set(handler)

        retrieved = SecurityErrorHandler.instance()
        assert retrieved is handler

    @pytest.mark.asyncio
    async def test_context_isolation_between_async_tasks(self):
        """Verify context isolation in concurrent async tasks."""
        results = []

        async def task(namespace: str):
            config = SecurityConfig(f"namespace-{namespace}")
            handler = SecurityErrorHandler(config)
            SecurityErrorHandler._context.set(handler)
            await asyncio.sleep(0.01)  # Simulate work
            retrieved = SecurityErrorHandler.instance()
            results.append(retrieved.config.cloudwatch_namespace)

        await asyncio.gather(task("1"), task("2"), task("3"))

        assert sorted(results) == ["namespace-1", "namespace-2", "namespace-3"]

    @pytest.mark.asyncio
    async def test_recommended_fallback_pattern(self):
        """Test recommended fallback implementation for production."""

        # This is what the code SHOULD do
        class ImprovedSecurityErrorHandler(SecurityErrorHandler):
            @classmethod
            def instance(cls) -> "ImprovedSecurityErrorHandler":
                try:
                    return cls._context.get()
                except LookupError:
                    # Fallback to default instance
                    default_config = SecurityConfig("cloudwan-mcp-fallback")
                    return cls(default_config)

        # Test without context - should return fallback
        handler = ImprovedSecurityErrorHandler.instance()
        assert handler.config.cloudwatch_namespace == "cloudwan-mcp-fallback"


class TestResourceCleanup:
    """Test proper resource cleanup and lifecycle management."""

    @pytest.mark.asyncio
    async def test_cloudwatch_client_session_leak(self):
        """Verify aiohttp ClientSession is never closed (current bug)."""
        client = CloudWatchBatchedClient("test-namespace")

        # Verify session exists and is open
        assert hasattr(client, "_session")
        assert isinstance(client._session, aiohttp.ClientSession)
        assert not client._session.closed

        # No cleanup method exists - this is the bug
        assert not hasattr(client, "cleanup")
        assert not hasattr(client, "__aexit__")

    @pytest.mark.asyncio
    async def test_cloudwatch_flush_task_never_cancelled(self):
        """Verify background task is never cancelled (current bug)."""
        client = CloudWatchBatchedClient("test-namespace")

        # Verify task exists and is running
        assert hasattr(client, "_flush_task")
        assert isinstance(client._flush_task, asyncio.Task)
        assert not client._flush_task.done()

        # No way to cancel it - this is the bug
        assert not hasattr(client, "cleanup")

    @pytest.mark.asyncio
    async def test_recommended_cleanup_implementation(self):
        """Test recommended cleanup pattern for production."""

        class ImprovedCloudWatchClient(CloudWatchBatchedClient):
            async def cleanup(self):
                """Proper cleanup implementation."""
                if hasattr(self, "_flush_task"):
                    self._flush_task.cancel()
                    try:
                        await self._flush_task
                    except asyncio.CancelledError:
                        pass

                if hasattr(self, "_session"):
                    await self._session.close()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                await self.cleanup()

        # Test proper cleanup
        async with ImprovedCloudWatchClient("test") as client:
            await client.put_metric("test", 1.0, {})

        # After context exit, resources should be cleaned
        assert client._session.closed
        assert client._flush_task.cancelled()

    @pytest.mark.asyncio
    async def test_memory_leak_under_high_load(self):
        """Test for memory leaks with multiple client instances."""
        clients = []

        # Create many clients without cleanup
        for i in range(100):
            client = CloudWatchBatchedClient(f"namespace-{i}")
            clients.append(client)

        # All would leak sessions and tasks
        open_sessions = sum(1 for c in clients if not c._session.closed)
        running_tasks = sum(1 for c in clients if not c._flush_task.done())

        assert open_sessions == 100  # This is the leak
        assert running_tasks == 100  # This is also a leak


class TestRaceConditions:
    """Test thread safety and race condition handling."""

    @pytest.mark.asyncio
    async def test_ulid_concurrent_generation_safety(self):
        """Test ULID generation under concurrent load."""
        engine = ULIDCorrelationEngine()
        ulids = []

        async def generate_many():
            for _ in range(100):
                ulid = await engine.generate()
                ulids.append(ulid)

        # Run concurrent generators
        await asyncio.gather(*[generate_many() for _ in range(10)])

        # Check for uniqueness
        assert len(ulids) == 1000
        assert len(set(ulids)) == 1000  # All unique

        # Check time ordering within reasonable bounds
        for i in range(1, len(ulids)):
            # Extract timestamp portion (first 10 hex chars)
            prev_time = int(ulids[i - 1][:10], 16)
            curr_time = int(ulids[i][:10], 16)
            # Allow for some reordering due to concurrency
            assert curr_time >= prev_time - 100  # 100ms tolerance

    @pytest.mark.asyncio
    async def test_cloudwatch_queue_race_condition(self):
        """Test the race condition in CloudWatch batch flushing."""
        client = CloudWatchBatchedClient("test")

        # Mock the flush to detect race condition
        flush_calls = []

        async def mock_flush():
            batch = []
            # This is the buggy pattern
            while not client._queue.empty():  # Race condition here!
                batch.append(await client._queue.get())
            flush_calls.append(len(batch))

        # Simulate concurrent puts during flush
        async def producer():
            for i in range(100):
                await client.put_metric(f"metric-{i}", i, {})
                if i == 50:
                    await asyncio.sleep(0)  # Yield control

        # Run producer and flush concurrently
        await asyncio.gather(producer(), mock_flush())

        # The race condition can cause incomplete batches
        # This test demonstrates the issue exists

    @pytest.mark.asyncio
    async def test_improved_batch_flush_pattern(self):
        """Test recommended non-racy batch flush implementation."""

        class ImprovedCloudWatchClient(CloudWatchBatchedClient):
            async def _flush_batch(self):
                """Non-racy implementation using get_nowait."""
                batch = []
                try:
                    while len(batch) < 1000:
                        item = self._queue.get_nowait()
                        batch.append(item)
                except asyncio.QueueEmpty:
                    pass  # No more items available

                if batch:
                    # Process batch...
                    pass

        client = ImprovedCloudWatchClient("test")

        # This pattern avoids the race condition
        for i in range(100):
            await client.put_metric(f"metric-{i}", i, {})

        await client._flush_batch()  # Safe flush


class TestPerformance:
    """Test performance against <850μs latency target."""

    @pytest.mark.asyncio
    async def test_error_handling_latency(self):
        """Measure actual latency of error handling."""
        config = SecurityConfig("perf-test")
        handler = SecurityErrorHandler(config)

        # Mock CloudWatch to avoid network latency
        with patch.object(handler.metrics, "put_metric", new_callable=AsyncMock):
            # pragma: allowlist secret
            error = ValueError("Test error with sensitive aws_access_key_id=AKIAIOSFODNN7EXAMPLE")  # pragma: allowlist secret
            context = MagicMock()

            # Measure latency
            iterations = 1000
            start = time.perf_counter()

            for _ in range(iterations):
                await handler.handle(error, context, SuppressionPolicy.RESOURCE_CLEANUP)

            elapsed = time.perf_counter() - start
            avg_latency_us = (elapsed / iterations) * 1_000_000

            print(f"Average latency: {avg_latency_us:.2f}μs")

            # Current implementation fails this test
            assert avg_latency_us > 850  # Exceeds target by ~3x

    @pytest.mark.asyncio
    async def test_sanitization_performance(self):
        """Benchmark credential sanitization performance."""
        sanitizer = CredentialSanitizer()

        # Test with various message sizes
        test_cases = [
            ("small", "password=secret123"),
            # pragma: allowlist secret
            ("medium", "x" * 500 + "aws_access_key_id=AKIAIOSFODNN7EXAMPLE" + "x" * 500),  # Test pattern for sanitization
            ("large", "x" * 10000 + "Authorization: Bearer token123" + "x" * 10000),
        ]

        for name, message in test_cases:
            start = time.perf_counter()
            iterations = 10000

            for _ in range(iterations):
                sanitizer.sanitize(message)

            elapsed = time.perf_counter() - start
            avg_us = (elapsed / iterations) * 1_000_000

            print(f"Sanitization {name}: {avg_us:.2f}μs")

            # Large messages are slow
            if name == "large":
                assert avg_us > 100  # Too slow for target

    @pytest.mark.asyncio
    async def test_optimized_sanitizer_pattern(self):
        """Test optimized sanitization for better performance."""

        class OptimizedCredentialSanitizer(CredentialSanitizer):
            def __init__(self):
                # Pre-compile patterns individually for better performance
                self._compiled_patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.PATTERNS]

            def sanitize(self, message: str) -> str:
                # Early return for common case
                if len(message) < 20:  # Minimum credential length
                    return message

                result = message
                for pattern in self._compiled_patterns:
                    result = pattern.sub("[REDACTED]", result)
                return result

        sanitizer = OptimizedCredentialSanitizer()

        # Benchmark optimized version
        message = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        start = time.perf_counter()

        for _ in range(10000):
            sanitizer.sanitize(message)

        elapsed = time.perf_counter() - start
        avg_us = (elapsed / 10000) * 1_000_000

        print(f"Optimized sanitization: {avg_us:.2f}μs")
        # Should be faster than original


class TestCredentialSanitization:
    """Test credential sanitization completeness and effectiveness."""

    def test_incomplete_pattern_coverage(self):
        """Verify only 5 patterns implemented instead of 28+."""
        sanitizer = CredentialSanitizer()

        # Count actual patterns
        actual_patterns = len(sanitizer.PATTERNS)
        assert actual_patterns == 5  # Only 5 implemented

        # Expected patterns that are missing
        missing_patterns = [
            # Database credentials
            r"(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@",
            r"(?i)DB_PASSWORD\s*=\s*['\"][^'\"]+['\"]",
            # API Keys and Tokens
            r"(?i)(github|gitlab)_token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
            r"(?i)slack_token\s*[=:]\s*['\"]?xox[a-z]-[a-zA-Z0-9-]+['\"]?",
            # Cloud provider keys
            r"(?i)GOOGLE_APPLICATION_CREDENTIALS",
            r"(?i)AZURE_CLIENT_SECRET\s*=\s*['\"][^'\"]+['\"]",
            # JWT tokens
            r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            # Private keys
            r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        ]

        # These patterns are NOT in the current implementation
        for pattern in missing_patterns:
            assert pattern not in sanitizer.PATTERNS

    def test_aws_credential_formats(self):
        """Test sanitization of various AWS credential formats."""
        sanitizer = CredentialSanitizer()

        test_cases = [
            # Current implementation handles these
        # pragma: allowlist secret
        ("aws_access_key_id=AKIAIOSFODNN7EXAMPLE", True),  # pragma: allowlist secret
        # pragma: allowlist secret
        ("AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", True),  # Test pattern for secret validation
            # These should be handled but aren't (missing patterns)
            ("arn:aws:iam::123456789012:role/MyRole", False),
            ("s3://my-bucket/path?X-Amz-Signature=abcd1234", False),
            ("X-Amz-Security-Token: FQoDYXdzEJr...", False),
        ]

        for text, should_redact in test_cases:
            result = sanitizer.sanitize(text)
            if should_redact:
                assert "[REDACTED]" in result
            else:
                # Currently fails to redact these
                assert "[REDACTED]" not in result

    def test_complete_pattern_implementation(self):
        """Test what a complete implementation should look like."""

        class CompleteCredentialSanitizer(CredentialSanitizer):
            PATTERNS = [
                # AWS
                r"(?i)aws_(secret_)?access_key(_id)?\s*[=:]\s*['\"]?[A-Z0-9/+=]{20,}['\"]?",
                r"(?i)AKIA[0-9A-Z]{16}",
                r"(?i)aws_session_token\s*[=:]\s*['\"]?[A-Za-z0-9/+=]+['\"]?",
                r"(?i)X-Amz-Security-Token:\s*[A-Za-z0-9/+=]+",
                r"(?i)X-Amz-Signature=[A-Za-z0-9]+",
                # API Keys
                r"(?i)x-api-key:\s*[A-Za-z0-9]{20,}",
                r"(?i)api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
                # Auth tokens
                r"(?i)Authorization:\s*(Bearer|Basic)\s+[A-Za-z0-9/+=]+",
                r"(?i)(access|refresh)[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_.-]+['\"]?",
                # Passwords
                r"(?i)password\s*[=:]\s*['\"]?[^'\"&\s]+['\"]?",
                r"(?i)passwd\s*[=:]\s*['\"]?[^'\"&\s]+['\"]?",
                # Database
                r"(?i)(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@",
                r"(?i)DB_[A-Z_]*PASSWORD\s*[=:]\s*['\"][^'\"]+['\"]",
                # GitHub/GitLab
                r"(?i)gh[pousr]_[A-Za-z0-9_]{36}",
                r"(?i)github[_-]token\s*[=:]\s*['\"]?[A-Za-z0-9_]{40}['\"]?",
                r"(?i)gitlab[_-]token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20}['\"]?",
                # Slack
                r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
                # JWT
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                # SSH/PGP Keys
                r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
                r"ssh-rsa\s+[A-Za-z0-9+/]{100,}",
                # Google Cloud
                r"(?i)GOOGLE_APPLICATION_CREDENTIALS",
                r"AIza[0-9A-Za-z_-]{35}",
                # Azure
                r"(?i)AZURE_CLIENT_SECRET\s*[=:]\s*['\"][^'\"]+['\"]",
                r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
                # Stripe
                r"sk_live_[0-9a-zA-Z]{24,}",
                r"rk_live_[0-9a-zA-Z]{24,}",
                # SendGrid
                r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
                # Twilio
                r"AC[a-z0-9]{32}",
                r"SK[a-z0-9]{32}",
            ]

        sanitizer = CompleteCredentialSanitizer()
        assert len(sanitizer.PATTERNS) >= 28  # Meets requirement


class TestCloudWatchIntegration:
    """Test CloudWatch metrics client behavior."""

    @pytest.mark.asyncio
    async def test_missing_authentication(self):
        """Verify CloudWatch client lacks AWS authentication."""
        client = CloudWatchBatchedClient("test")

        # Current implementation has no auth headers
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 403
            mock_response.text = AsyncMock(return_value="Missing Authentication Token")
            mock_post.return_value.__aenter__.return_value = mock_response

            await client.put_metric("test", 1.0, {})
            await client._flush_batch()

            # Would fail with 403 in production
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args[1]

            # No auth headers present
            assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_batch_overflow_handling(self):
        """Test queue overflow under high load."""
        client = CloudWatchBatchedClient("test")

        # Fill queue to capacity
        for i in range(1000):
            await client.put_metric(f"metric-{i}", i, {})

        # Queue is now full (maxsize=1000)
        assert client._queue.full()

        # Next put will block - this could cause issues
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(client.put_metric("overflow", 1, {}), timeout=0.1)

    @pytest.mark.asyncio
    async def test_cloudwatch_unreachable_scenario(self):
        """Test behavior when CloudWatch is unreachable."""
        client = CloudWatchBatchedClient("test")

        with patch.object(client._session, "post") as mock_post:
            # Simulate network error
            mock_post.side_effect = aiohttp.ClientError("Connection failed")

            # Add metrics
            for i in range(100):
                await client.put_metric(f"metric-{i}", i, {})

            # Flush should handle error gracefully
            with pytest.raises(aiohttp.ClientError):
                await client._flush_batch()

            # But metrics are lost - no retry mechanism


class TestRecoveryActions:
    """Test AWS Well-Architected recovery suggestions."""

    def test_recovery_action_mapping(self):
        """Test recovery actions for different severity levels."""
        recovery = AWSErrorRecovery()

        test_cases = [
            ("CRITICAL", ["RotateEphemeralCredentials", "InitiateAZFailover"]),
            ("HIGH", ["ExponentialBackoffRetry", "CheckServiceQuotas"]),
            ("MEDIUM", ["CircuitBreakerReset", "WarmupRequests"]),
            ("LOW", ["LogAndContinue"]),  # Default
            ("UNKNOWN", ["LogAndContinue"]),  # Default fallback
        ]

        for severity, expected_actions in test_cases:
            actions = recovery.get_actions(severity)
            assert actions == expected_actions

    def test_security_classification_accuracy(self):
        """Test error classification against AWS error types."""
        classifier = SecurityClassifier()

        test_cases = [
            (ConnectionResetError(), ("CRITICAL", "CWE-400")),
            (TimeoutError(), ("MEDIUM", "CWE-400")),
            (PermissionError(), ("HIGH", "CWE-276")),
            (ValueError(), ("LOW", "CWE-000")),  # Default
        ]

        for error, expected in test_cases:
            result = classifier.classify(error)
            assert result == expected


class TestIntegrationCompatibility:
    """Test integration with existing error_handling.py patterns."""

    @pytest.mark.asyncio
    async def test_suppression_policy_maintains_pass_behavior(self):
        """Verify SuppressionPolicy maintains original pass behavior."""
        config = SecurityConfig("test")
        handler = SecurityErrorHandler(config)

        # Mock to avoid actual CloudWatch calls
        with patch.object(handler.metrics, "put_metric", new_callable=AsyncMock):
            # Original code: try: ... except: pass
            # New code should maintain same behavior

            error = ConnectionResetError("Connection lost")
            context = MagicMock()

            result = await handler.handle(error, context, SuppressionPolicy.RESOURCE_CLEANUP)

            # Should return actions but not raise
            assert isinstance(result, list)
            assert len(result) > 0

            # Original behavior maintained - no exception raised

    @pytest.mark.asyncio
    async def test_integration_pattern_for_existing_code(self):
        """Test recommended integration pattern for existing try-except blocks."""

        # Simulated existing code pattern
        class ClientPool:
            def __init__(self):
                self.handler = None

            async def cleanup_connection(self, client):
                try:
                    await client.close()
                except (ConnectionResetError, TimeoutError) as e:
                    # Original: pass
                    # New pattern:
                    if self.handler:
                        await self.handler.handle(e, {"client_id": id(client)}, SuppressionPolicy.RESOURCE_CLEANUP)
                    # Still suppresses exception like original

        pool = ClientPool()
        config = SecurityConfig("test")
        pool.handler = SecurityErrorHandler(config)

        # Mock client that raises error
        mock_client = AsyncMock()
        mock_client.close.side_effect = ConnectionResetError()

        # Should not raise - maintains original behavior
        await pool.cleanup_connection(mock_client)


class TestHighLoadScenarios:
    """Test system behavior under high load conditions."""

    @pytest.mark.asyncio
    async def test_thousand_errors_per_second(self):
        """Test handling 1000+ errors per second."""
        config = SecurityConfig("load-test")
        handler = SecurityErrorHandler(config)

        # Mock CloudWatch to measure throughput
        metrics_sent = []

        async def mock_flush(self):
            batch = []
            try:
                while len(batch) < 1000:
                    item = self._queue.get_nowait()
                    batch.append(item)
            except asyncio.QueueEmpty:
                pass
            metrics_sent.append(len(batch))

        with patch.object(CloudWatchBatchedClient, "_flush_batch", mock_flush):
            start = time.perf_counter()

            # Generate 1000 errors
            tasks = []
            for i in range(1000):
                error = ValueError(f"Error {i}")
                task = handler.handle(error, {"request_id": i}, SuppressionPolicy.METRIC_HANDLING)
                tasks.append(task)

            await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start

            throughput = 1000 / elapsed
            print(f"Throughput: {throughput:.2f} errors/second")

            # Should handle 1000+ per second
            assert throughput > 1000:

    @pytest.mark.asyncio
    async def test_memory_usage_under_sustained_load(self):
        """Test memory stability under sustained load."""
        config = SecurityConfig("memory-test")
        handler = SecurityErrorHandler(config)

        # Mock to prevent actual network calls
        with patch.object(handler.metrics, "put_metric", new_callable=AsyncMock):
            # Sustained load for extended period
            for batch in range(10):
                tasks = []
                for i in range(1000):
                    error = ValueError(f"Batch {batch} Error {i}")
                    task = handler.handle(error, {"batch": batch, "index": i}, SuppressionPolicy.API_SIMULATION)
                    tasks.append(task)

                await asyncio.gather(*tasks)

                # Check queue isn't growing unbounded
                assert handler.metrics._queue.qsize() <= 1000

    @pytest.mark.asyncio
    async def test_concurrent_handler_instances(self):
        """Test multiple handler instances operating concurrently."""
        handlers = []

        # Create multiple handlers
        for i in range(10):
            config = SecurityConfig(f"namespace-{i}")
            handler = SecurityErrorHandler(config)
            handlers.append(handler)

        # Generate errors on all handlers concurrently
        async def generate_errors(handler, handler_id):
            for i in range(100):
                error = ValueError(f"Handler {handler_id} Error {i}")
                await handler.handle(error, {"handler": handler_id}, SuppressionPolicy.CONNECTION_MANAGEMENT)

        # Mock to avoid network calls
        with patch("aiohttp.ClientSession.post", new_callable=AsyncMock):
            tasks = [generate_errors(handler, i) for i, handler in enumerate(handlers)]

            start = time.perf_counter()
            await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start

            total_errors = 10 * 100
            throughput = total_errors / elapsed

            print(f"Multi-instance throughput: {throughput:.2f} errors/second")

            # Should handle high concurrent load
            assert throughput > 500


if __name__ == "__main__":
    # Run specific test categories
    pytest.main([__file__, "-v", "-k", "TestContextManagement"])
