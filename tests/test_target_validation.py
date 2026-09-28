import pytest

from app.core.exceptions import AuthorizationRequired, ScopeViolation, ValidationError
from app.core.security import ScopeValidator


def test_requires_authorization():
    with pytest.raises(AuthorizationRequired):
        ScopeValidator().validate("192.168.1.2", "192.168.1.0/24", False)


def test_target_must_be_inside_scope():
    with pytest.raises(ScopeViolation):
        ScopeValidator().validate("10.0.0.2", "192.168.1.0/24", True)


def test_valid_cidr_and_limit():
    result = ScopeValidator(max_targets=256).validate("192.168.1.0/24", "192.168.1.0/24", True)
    assert result.count == 256
    with pytest.raises(ScopeViolation):
        ScopeValidator(max_targets=10).validate("192.168.1.0/24", None, True)


def test_rejects_command_like_target():
    with pytest.raises(ValidationError):
        ScopeValidator().validate("127.0.0.1;whoami", None, True)


def test_denylist_rejects_overlapping_network():
    with pytest.raises(ScopeViolation):
        ScopeValidator(denylist=["192.168.1.128/25"], max_targets=256).validate(
            "192.168.1.0/24", "192.168.1.0/24", True
        )
