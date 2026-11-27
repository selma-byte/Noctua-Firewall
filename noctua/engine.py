import ipaddress

DEFAULTS = {"in": "deny", "out": "allow"}


def port_matches(rule_port, packet_port):
    if rule_port is None:
        return True
    if packet_port is None:
        return False
    if isinstance(rule_port, str):
        low, high = (int(p) for p in rule_port.split("-"))
        return low <= packet_port <= high
    return rule_port == packet_port


def address_matches(rule_address, packet_address):
    if rule_address == "any":
        return True
    if packet_address is None:
        return False
    network = ipaddress.ip_network(rule_address, strict=False)
    return ipaddress.ip_address(packet_address) in network


def matches(rule, packet):
    if rule.get("direction", "in") != packet.get("direction", "in"):
        return False
    if rule["protocol"] != packet["protocol"]:
        return False
    if not port_matches(rule["port"], packet.get("port")):
        return False
    if not address_matches(rule["source"], packet.get("source")):
        return False
    if not address_matches(rule.get("destination", "any"), packet.get("destination")):
        return False
    return True


def decide(rules, packet):
    """First matching rule wins. With no match, incoming is dropped and
    outgoing is allowed."""
    for rule in rules:
        if matches(rule, packet):
            return rule["action"]
    return DEFAULTS[packet.get("direction", "in")]