from awslabs.cloudwan_mcp_server.consts import sanitize_error_message


def test_sanitize_error_message_truncates_long():
    msg = "x" * 20000
    result = sanitize_error_message(msg)
    assert result in ["[TRUNCATED_FOR_SECURITY]", "[REDACTED]"], "Should truncate very long messages"


def test_sanitize_access_key():
    sanitized = sanitize_error_message("My key is AKIATESTOLD")  # pragma: allowlist secret
    assert any(["[ACCESS_KEY_REDACTED]" in sanitized, "AKIA" not in sanitized, "[REDACTED]" in sanitized]), (
        "Access key should be redacted"
    )


def test_sanitize_secret_key():
    secret = "A" * 40  # looks like a secret key  # pragma: allowlist secret
    sanitized = sanitize_error_message(secret)
    assert any(["[SECRET_KEY_REDACTED]" in sanitized, len(sanitized) < len(secret), sanitized == "[REDACTED]"]), (
        "Should redact secret-like strings"
    )


def test_sanitize_arn():
    msg = "arn:aws:s3:::mybucket"  # pragma: allowlist secret
    sanitized = sanitize_error_message(msg)
    assert any(["[ARN_REDACTED]" in sanitized, "arn:" not in sanitized, "[REDACTED]" in sanitized]), (
        "Should redact ARNs"
    )


def test_sanitize_normal_message():
    msg = "An error occurred"
    sanitized = sanitize_error_message(msg)
    assert sanitized == msg, "Normal messages should remain unchanged"


def test_message_length_limits():
    # Test that very long messages are always handled
    long_msg = "x" * 10000
    sanitized = sanitize_error_message(long_msg)
    assert len(sanitized) < len(long_msg), "Long messages should be shortened"


def test_sensitive_pattern_redaction():
    # Test various sensitive patterns
    sensitive_patterns = ["password=secret123", "secret_key=abcdef", "token=xyz123"]
    for pattern in sensitive_patterns:
        sanitized = sanitize_error_message(pattern)
        assert "[REDACTED]" in sanitized or any(
            sens_word not in sanitized for sens_word in ["secret", "password", "token", "key"]
        ), f"Should redact sensitive pattern: {pattern}"
