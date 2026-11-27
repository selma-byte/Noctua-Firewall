def rule_line(rule):
    parts = []
    if rule["source"] != "any":
        parts.append(f"ip saddr {rule['source']}")

    proto = rule["protocol"]
    if proto == "icmp":
        parts.append("meta l4proto icmp")
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