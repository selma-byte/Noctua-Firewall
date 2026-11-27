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