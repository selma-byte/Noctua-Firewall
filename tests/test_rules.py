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

def test_port_range_is_kept():
    rule = check_rule({"action": "allow", "port": "8000-8100"}, 1)
    assert rule["port"] == "8000-8100"


def test_backwards_range_is_rejected():
    with pytest.raises(RuleError):
        check_rule({"action": "allow", "port": "9000-8000"}, 1)

def test_log_must_be_true_or_false():
    with pytest.raises(RuleError):
        check_rule({"action": "deny", "log": "yes please"}, 1)


def test_log_defaults_to_off():
    assert check_rule({"action": "deny"}, 1)["log"] is False
