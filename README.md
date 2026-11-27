# Noctua-Firewall

[![tests](https://github.com/selma-byte/Noctua-Firewall/actions/workflows/tests.yml/badge.svg)](https://github.com/selma-byte/Noctua-Firewall/actions/workflows/tests.yml)

Named after the little owl, a night watcher.

Noctua reads firewall rules from a YAML file, checks them, and turns them
into an nftables ruleset. Anything the rules don't mention is dropped.

## Install

Needs Python 3.9 or newer.

~~~
git clone https://github.com/selma-byte/Noctua-Firewall.git
cd Noctua-Firewall
pip install -e .
~~~

## Writing rules

Rules live in a YAML file. See `examples/rules.yml`.

~~~yaml
rules:
  - action: allow
    protocol: tcp
    port: 22
    source: 192.168.1.0/24
  - action: allow
    protocol: tcp
    port: 443
  - action: deny
    protocol: tcp
    port: 23
~~~

| Field    | Values                                | Default  |
|----------|---------------------------------------|----------|
| action   | `allow` or `deny`                     | required |
| protocol | `tcp`, `udp`, `icmp`                  | `tcp`    |
| port     | 1 to 65535 (not for icmp)             | any      |
| source   | an IPv4 address or network, or `any`  | `any`    |

Bad rules are refused with the rule number in the message.

## Commands

Print the nftables ruleset and change nothing:

~~~
noctua show examples/rules.yml
~~~

Ask what would happen to one packet:

~~~
noctua test examples/rules.yml --proto tcp --port 22 --src 192.168.1.20
~~~

Load the rules (Linux, root, nftables installed). Without `--yes` it only
prints what it would do:

~~~
noctua apply examples/rules.yml
noctua apply examples/rules.yml --yes
~~~

## How it decides

- Rules are read from top to bottom and the first match wins.
- If nothing matches, the packet is dropped. The generated chain has
  `policy drop`.
- Replies to connections the machine started are allowed
  (`ct state established,related`), otherwise its own web browsing would break.
- Local traffic on the loopback interface is allowed.
- `apply` is a dry run unless `--yes` is given, and the ruleset goes through
  `nft -c` first, so a broken ruleset is never loaded.

## Limits

- Incoming traffic only (the input chain).
- IPv4 source addresses only.
- No logging yet.

## Be careful with apply

A wrong rule can cut you off from a machine you are connected to over SSH.
Try `apply --yes` inside a virtual machine first, and keep a rule that allows
your own address.

## Tests

~~~
pip install pytest
python -m pytest
~~~

## License

MIT