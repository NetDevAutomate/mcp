from awslabs.cloudwan_mcp_server import server


def test_aws_config_defaults():
    cfg = server.AWSConfig()
    assert cfg.default_region == server.DEFAULT_AWS_REGION
    assert cfg.log_level == server.DEFAULT_LOG_LEVEL
    # Profile defaults to None
    assert cfg.aws_profile is None


def test_aws_config_env_override(monkeypatch):
    monkeypatch.setenv("CLOUDWAN_DEFAULT_REGION", "us-west-2")
    monkeypatch.setenv("CLOUDWAN_LOG_LEVEL", "DEBUG")
    cfg = server.AWSConfig()
    assert cfg.default_region == "us-west-2"
    assert cfg.log_level == "DEBUG"


def test_get_aws_client_with_profile(monkeypatch):
    monkeypatch.setenv("CLOUDWAN_AWS_PROFILE", "secure-profile")  # pragma: allowlist secret
    cfg = server.AWSConfig()
    client = server.get_aws_client("ec2", region="us-east-1")
    assert client is not None
