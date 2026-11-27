import yaml

VALID_ACTIONS = {"allow", "deny"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp"}


class RuleError(ValueError):
    """Raised when the rules file is wrong."""


def load_rules(path):
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "rules" not in data:
        raise RuleError("file needs a top-level 'rules' list")
    return [check_rule(r, n) for n, r in enumerate(data["rules"], start=1)]


def check_rule(rule, number):
    if rule.get("action") not in VALID_ACTIONS:
        raise RuleError(f"rule {number}: action must be allow or deny")

    proto = rule.get("protocol", "tcp")
    if proto not in VALID_PROTOCOLS:
        raise RuleError(f"rule {number}: unknown protocol {proto!r}")

    port = rule.get("port")
    if port is not None:
        if proto == "icmp":
            raise RuleError(f"rule {number}: icmp has no ports")
        if not 1 <= int(port) <= 65535:
            raise RuleError(f"rule {number}: port {port} is out of range")

    return {
        "action": rule["action"],
        "protocol": proto,
        "port": int(port) if port is not None else None,
        "source": rule.get("source", "any"),
    }