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