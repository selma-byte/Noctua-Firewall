import pytest

from noctua.rules import RuleError, check_rule


def test_port_zero_is_rejected():
    with pytest.raises(RuleError):
        check_rule({"action": "allow", "port": 0}, 1)


def test_unknown_protocol_is_rejected():
    with pytest.raises(RuleError):
        check_rule({"action": "allow", "protocol": "gre"}, 1)


def test_defaults_are_filled_in():
    rule = check_rule({"action": "deny"}, 1)
    assert rule["protocol"] == "tcp"
    assert rule["source"] == "any"