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


def parse_port(value, number):
    """A single port comes back as an int, a range as the text 'low-high'."""
    text = str(value)
    if "-" in text:
        low_text, _, high_text = text.partition("-")
        try:
            low, high = int(low_text), int(high_text)
        except ValueError:
            raise RuleError(f"rule {number}: bad port range {text!r}")
        if not 1 <= low <= high <= 65535:
            raise RuleError(f"rule {number}: port range {text} is not valid")
        return f"{low}-{high}"
    try:
        port = int(text)
    except ValueError:
        raise RuleError(f"rule {number}: bad port {text!r}")
    if not 1 <= port <= 65535:
        raise RuleError(f"rule {number}: port {port} is out of range")
    return port


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
        port = parse_port(port, number)

    log = rule.get("log", False)
    if not isinstance(log, bool):
        raise RuleError(f"rule {number}: log must be true or false")

    return {
        "action": rule["action"],
        "protocol": proto,
        "port": port,
        "source": rule.get("source", "any"),
        "log": log,
    }