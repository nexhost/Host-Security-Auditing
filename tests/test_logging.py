from app.core.logging import redact


def test_redacts_common_secrets():
    assert "secret-value" not in redact("Authorization: secret-value")
    assert "abc123" not in redact("api_key=abc123")

