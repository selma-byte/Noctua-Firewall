from noctua.engine import decide

RULES = [
    {"action": "allow", "protocol": "tcp", "port": 22, "source": "192.168.1.0/24"},
    {"action": "deny", "protocol": "tcp", "port": 23, "source": "any"},
    {"action": "allow", "protocol": "icmp", "port": None, "source": "any"},
]


def test_ssh_from_lan_gets_in():
    pkt = {"protocol": "tcp", "port": 22, "source": "192.168.1.15"}
    assert decide(RULES, pkt) == "allow"


def test_ssh_from_outside_is_dropped():
    pkt = {"protocol": "tcp", "port": 22, "source": "8.8.8.8"}
    assert decide(RULES, pkt) == "deny"


def test_ping_is_allowed():
    pkt = {"protocol": "icmp", "source": "10.0.0.9"}
    assert decide(RULES, pkt) == "allow"


def test_unlisted_traffic_falls_to_deny():
    pkt = {"protocol": "udp", "port": 5000, "source": "10.0.0.2"}
    assert decide(RULES, pkt) == "deny"


def test_port_range_matches_inside_but_not_outside():
    rules = [{"action": "allow", "protocol": "tcp", "port": "8000-8100", "source": "any"}]
    inside = {"protocol": "tcp", "port": 8050, "source": "1.2.3.4"}
    outside = {"protocol": "tcp", "port": 8101, "source": "1.2.3.4"}
    assert decide(rules, inside) == "allow"
    assert decide(rules, outside) == "deny"


def test_ipv6_source_matches_an_ipv6_network():
    rules = [{"action": "allow", "protocol": "tcp", "port": 22, "source": "2001:db8::/32"}]
    pkt = {"protocol": "tcp", "port": 22, "source": "2001:db8::5"}
    assert decide(rules, pkt) == "allow"


def test_ipv4_rule_does_not_match_an_ipv6_packet():
    rules = [{"action": "allow", "protocol": "tcp", "port": 22, "source": "192.168.1.0/24"}]
    pkt = {"protocol": "tcp", "port": 22, "source": "2001:db8::5"}
    assert decide(rules, pkt) == "deny"