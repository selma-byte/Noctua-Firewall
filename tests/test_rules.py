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
    assert rule["direction"] == "in"


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


def test_ipv6_network_is_accepted():
    rule = check_rule({"action": "allow", "source": "2001:db8::/32"}, 1)
    assert rule["source"] == "2001:db8::/32"


def test_bad_source_is_rejected():
    with pytest.raises(RuleError):
        check_rule({"action": "allow", "source": "192.168.1.0/99"}, 1)


def test_outgoing_rule_takes_a_destination():
    rule = check_rule(
        {"action": "deny", "direction": "out", "destination": "203.0.113.0/24"}, 1
    )
    assert rule["direction"] == "out"
    assert rule["destination"] == "203.0.113.0/24"


def test_outgoing_rule_refuses_a_source():
    with pytest.raises(RuleError):
        check_rule({"action": "deny", "direction": "out", "source": "10.0.0.0/8"}, 1)


def test_incoming_rule_refuses_a_destination():
    with pytest.raises(RuleError):
        check_rule({"action": "deny", "destination": "10.0.0.0/8"}, 1)


def test_unknown_direction_is_rejected():
    with pytest.raises(RuleError):
        check_rule({"action": "deny", "direction": "sideways"}, 1)