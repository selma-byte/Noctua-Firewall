import ipaddress


def port_matches(rule_port, packet_port):
    if rule_port is None:
        return True
    if packet_port is None:
        return False
    if isinstance(rule_port, str):
        low, high = (int(p) for p in rule_port.split("-"))
        return low <= packet_port <= high
    return rule_port == packet_port


def matches(rule, packet):
    if rule["protocol"] != packet["protocol"]:
        return False
    if not port_matches(rule["port"], packet.get("port")):
        return False
    if rule["source"] != "any":
        network = ipaddress.ip_network(rule["source"], strict=False)
        if ipaddress.ip_address(packet["source"]) not in network:
            return False
    return True


def decide(rules, packet):
    """First matching rule wins. If nothing matches, the packet is dropped."""
    for rule in rules:
        if matches(rule, packet):
            return rule["action"]
    return "deny"