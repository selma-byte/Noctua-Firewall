from noctua.nft import rule_line, to_nft


def test_ssh_rule_text():
    rule = {"action": "allow", "protocol": "tcp", "port": 22, "source": "192.168.1.0/24"}
    assert rule_line(rule) == "ip saddr 192.168.1.0/24 tcp dport 22 accept"


def test_deny_becomes_drop():
    rule = {"action": "deny", "protocol": "tcp", "port": 23, "source": "any"}
    assert rule_line(rule) == "tcp dport 23 drop"


def test_icmp_has_no_port():
    rule = {"action": "allow", "protocol": "icmp", "port": None, "source": "any"}
    assert rule_line(rule) == "meta l4proto icmp accept"


def test_policy_is_drop():
    assert "policy drop" in to_nft([])