import ipaddress


def family(address):
    """4 or 6 for an address or network, None for 'any'."""
    if address == "any":
        return None
    return ipaddress.ip_network(address, strict=False).version


def rule_line(rule):
    parts = []
    outgoing = rule.get("direction", "in") == "out"
    address = rule["destination"] if outgoing else rule["source"]
    label = "daddr" if outgoing else "saddr"

    version = family(address)
    if version == 4:
        parts.append(f"ip {label} {address}")
    elif version == 6:
        parts.append(f"ip6 {label} {address}")

    proto = rule["protocol"]
    if proto == "icmp":
        if version == 4:
            parts.append("meta l4proto icmp")
        elif version == 6:
            parts.append("meta l4proto ipv6-icmp")
        else:
            parts.append("meta l4proto { icmp, ipv6-icmp }")
    elif rule["port"] is not None:
        parts.append(f"{proto} dport {rule['port']}")
    else:
        parts.append(f"meta l4proto {proto}")

    if rule.get("log"):
        parts.append('log prefix "noctua: "')

    parts.append("accept" if rule["action"] == "allow" else "drop")
    return " ".join(parts)


def to_nft(rules):
    incoming = [r for r in rules if r.get("direction", "in") == "in"]
    outgoing = [r for r in rules if r.get("direction", "in") == "out"]

    lines = [
        "table inet noctua {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    ct state established,related accept",
        '    iif "lo" accept',
    ]
    lines += [f"    {rule_line(r)}" for r in incoming]
    lines += [
        "  }",
        "  chain output {",
        "    type filter hook output priority 0; policy accept;",
        '    oif "lo" accept',
    ]
    lines += [f"    {rule_line(r)}" for r in outgoing]
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"