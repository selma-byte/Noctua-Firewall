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


def test_outgoing_deny_matches_an_outgoing_packet():
    rules = [{"action": "deny", "direction": "out", "protocol": "tcp", "port": 6667,
              "source": "any", "destination": "any"}]
    pkt = {"direction": "out", "protocol": "tcp", "port": 6667, "destination": "203.0.113.9"}
    assert decide(rules, pkt) == "deny"


def test_outgoing_traffic_is_allowed_by_default():
    pkt = {"direction": "out", "protocol": "tcp", "port": 80, "destination": "8.8.8.8"}
    assert decide([], pkt) == "allow"


def test_incoming_rule_ignores_outgoing_packets():
    rules = [{"action": "deny", "protocol": "tcp", "port": 80, "source": "any"}]
    pkt = {"direction": "out", "protocol": "tcp", "port": 80, "destination": "8.8.8.8"}
    assert decide(rules, pkt) == "allow"


def test_destination_network_is_checked():
    rules = [{"action": "deny", "direction": "out", "protocol": "tcp", "port": None,
              "source": "any", "destination": "203.0.113.0/24"}]
    blocked = {"direction": "out", "protocol": "tcp", "port": 80, "destination": "203.0.113.9"}
    free = {"direction": "out", "protocol": "tcp", "port": 80, "destination": "8.8.8.8"}
    assert decide(rules, blocked) == "deny"
    assert decide(rules, free) == "allow"