from noctua.nft import rule_line, to_nft


def test_ssh_rule_text():
    rule = {"action": "allow", "protocol": "tcp", "port": 22, "source": "192.168.1.0/24"}
    assert rule_line(rule) == "ip saddr 192.168.1.0/24 tcp dport 22 accept"


def test_deny_becomes_drop():
    rule = {"action": "deny", "protocol": "tcp", "port": 23, "source": "any"}
    assert rule_line(rule) == "tcp dport 23 drop"


def test_icmp_without_a_source_covers_both_families():
    rule = {"action": "allow", "protocol": "icmp", "port": None, "source": "any"}
    assert rule_line(rule) == "meta l4proto { icmp, ipv6-icmp } accept"


def test_policy_is_drop():
    assert "policy drop" in to_nft([])


def test_port_range_text():
    rule = {"action": "allow", "protocol": "tcp", "port": "8000-8100", "source": "any"}
    assert rule_line(rule) == "tcp dport 8000-8100 accept"


def test_log_goes_before_the_verdict():
    rule = {"action": "deny", "protocol": "tcp", "port": 23, "source": "any", "log": True}
    assert rule_line(rule) == 'tcp dport 23 log prefix "noctua: " drop'


def test_ipv6_source_uses_ip6_saddr():
    rule = {"action": "allow", "protocol": "tcp", "port": 22, "source": "2001:db8::/32"}
    assert rule_line(rule) == "ip6 saddr 2001:db8::/32 tcp dport 22 accept"


def test_icmp_follows_the_source_family():
    v4 = {"action": "allow", "protocol": "icmp", "port": None, "source": "10.0.0.0/8"}
    v6 = {"action": "allow", "protocol": "icmp", "port": None, "source": "2001:db8::/32"}
    assert rule_line(v4) == "ip saddr 10.0.0.0/8 meta l4proto icmp accept"
    assert rule_line(v6) == "ip6 saddr 2001:db8::/32 meta l4proto ipv6-icmp accept"


def test_outgoing_rule_uses_daddr():
    rule = {"action": "deny", "direction": "out", "protocol": "tcp", "port": None,
            "source": "any", "destination": "203.0.113.0/24"}
    assert rule_line(rule) == "ip daddr 203.0.113.0/24 meta l4proto tcp drop"


def test_outgoing_rules_go_in_the_output_chain():
    rules = [
        {"action": "allow", "protocol": "tcp", "port": 22, "source": "any"},
        {"action": "deny", "direction": "out", "protocol": "tcp", "port": 6667,
         "source": "any", "destination": "any"},
    ]
    text = to_nft(rules)
    input_part, output_part = text.split("chain output")
    assert "tcp dport 22 accept" in input_part
    assert "tcp dport 6667 drop" in output_part
    assert "tcp dport 6667" not in input_part


def test_output_chain_accepts_by_default():
    assert "hook output priority 0; policy accept;" in to_nft([])


def test_output_chain_lets_loopback_through():
    assert 'oif "lo" accept' in to_nft([])