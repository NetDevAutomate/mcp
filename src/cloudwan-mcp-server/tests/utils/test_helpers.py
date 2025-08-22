import json

def assert_success_response(result: str):
    data = json.loads(result)
    assert data["success"] is True
    return data

def assert_error_response(result: str):
    data = json.loads(result)
    assert data["success"] is False
    assert "error" in data
    return data

def validate_aws_response_structure(response: dict, keys: list[str]):
    for key in keys:
        assert key in response, f"Missing {key}"

def simulate_error_message(message: str) -> str:
    """Return sanitized error message for testing."""
    from awslabs.cloudwan_mcp_server.consts import sanitize_error_message
    return sanitize_error_message(message)