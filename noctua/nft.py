import ipaddress


def family(source):
    """4 or 6 for an address or network, None for 'any'."""
    if source == "any":
        return None
    return ipaddress.ip_network(source, strict=False).version


def rule_line(rule):
    parts = []
    version = family(rule["source"])
    if version == 4:
        parts.append(f"ip saddr {rule['source']}")
    elif version == 6:
        parts.append(f"ip6 saddr {rule['source']}")

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
    lines = [
        "table inet noctua {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    ct state established,related accept",
        '    iif "lo" accept',
    ]
    lines += [f"    {rule_line(r)}" for r in rules]
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"