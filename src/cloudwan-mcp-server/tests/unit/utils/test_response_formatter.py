import json
import pytest

from awslabs.cloudwan_mcp_server import server

def test_safe_json_dumps_handles_non_serializable():
    class Obj:
        def __str__(self):
            return "OBJ"
    d = {"a": Obj()}
    result = server.safe_json_dumps(d)
    data = json.loads(result)
    assert data["a"] == "OBJ"

def test_handle_aws_error_formats_error():
    e = Exception("boom with arn:aws:s3:::bucket and key AKIA9999999999999999")
    out = server.handle_aws_error(e, "op1")
    data = json.loads(out)
    assert data["success"] is False
    assert data["error"]["operation"] == "op1"
    assert "code" in data["error"]
    assert "message" in data["error"]