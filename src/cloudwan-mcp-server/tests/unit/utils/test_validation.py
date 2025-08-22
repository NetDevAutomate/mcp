import pytest
from awslabs.cloudwan_mcp_server.consts import sanitize_error_message

def test_sanitize_error_message_truncates_long():
    msg = "x" * 20000
    result = sanitize_error_message(msg)
    assert result == "[TRUNCATED_FOR_SECURITY]"

def test_sanitize_access_key():
    msg = "My key is AKIA1234567890ABCDEF"  # 20 chars total: AKIA + 16 chars
    sanitized = sanitize_error_message(msg)
    assert "[ACCESS_KEY_REDACTED]" in sanitized

def test_sanitize_secret_key():
    secret = "A" * 40  # looks like a secret key
    sanitized = sanitize_error_message(secret)
    assert "[SECRET_KEY_REDACTED]" in sanitized

def test_sanitize_arn():
    msg = "arn:aws:s3:::mybucket"
    sanitized = sanitize_error_message(msg)
    assert "[ARN_REDACTED]" in sanitized

def test_sanitize_normal_message():
    msg = "An error occurred"
    sanitized = sanitize_error_message(msg)
    assert sanitized == msg