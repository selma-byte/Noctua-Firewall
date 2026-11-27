import ipaddress


def matches(rule, packet):
    if rule["protocol"] != packet["protocol"]:
        return False
    if rule["port"] is not None and rule["port"] != packet.get("port"):
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