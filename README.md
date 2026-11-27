# Noctua-Firewall

[![tests](https://github.com/selma-byte/Noctua-Firewall/actions/workflows/tests.yml/badge.svg)](https://github.com/selma-byte/Noctua-Firewall/actions/workflows/tests.yml)

Named after the little owl, a night watcher.

Noctua reads firewall rules from a YAML file, checks them, and turns them
into an nftables ruleset. Incoming traffic that the rules don't mention is
dropped.

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
    port: 22
    source: "2001:db8::/32"
  - action: allow
    protocol: tcp
    port: 8000-8100
  - action: deny
    protocol: tcp
    port: 23
    log: true
  - action: deny
    direction: out
    protocol: tcp
    port: 6667
    log: true
~~~

| Field       | Values                                                  | Default  |
|-------------|---------------------------------------------------------|----------|
| action      | `allow` or `deny`                                       | required |
| direction   | `in` or `out`                                           | `in`     |
| protocol    | `tcp`, `udp`, `icmp`                                    | `tcp`    |
| port        | 1 to 65535, or a range like `8000-8100` (not for icmp)  | any      |
| source      | IPv4 or IPv6 address or network, or `any` (`in` rules)  | `any`    |
| destination | IPv4 or IPv6 address or network, or `any` (`out` rules) | `any`    |
| log         | `true` to record matching packets in the system log     | `false`  |

An incoming rule uses `source` and an outgoing rule uses `destination`. Mixing
them up is refused. The port is always the destination port, so on an outgoing
rule it is the port of the remote service.

A port range must go from the lower number to the higher one, so `9000-8000`
is refused. A source or destination that is not a valid address or network is
refused too. Bad rules are refused with the rule number in the message.

## IPv6

Put IPv6 addresses in quotes, because YAML can misread the colons.
IPv4 addresses become `ip saddr` or `ip daddr` and IPv6 addresses become
`ip6 saddr` or `ip6 daddr`.

An `icmp` rule means ICMP for IPv4 and ICMPv6 for IPv6. With no address it
covers both, which matters because IPv6 stops working if ICMPv6 is blocked.

## Incoming and outgoing

The generated table has two chains.

- `input` has the policy `drop`. Only what the rules allow gets in, plus
  replies to connections the machine started and local traffic.
- `output` has the policy `accept`, so the machine keeps working with no
  rules at all. Outgoing rules are mostly `deny`, for example to block a port
  or a network. An `allow` placed before a `deny` works as an exception.

## Commands

Print the nftables ruleset and change nothing:

~~~
noctua show examples/rules.yml
~~~

Ask what would happen to one packet:

~~~
noctua test examples/rules.yml --proto tcp --port 22 --src 192.168.1.20
noctua test examples/rules.yml --direction out --proto tcp --port 6667 --dst 203.0.113.9
~~~

Load the rules (Linux, root, nftables installed). Without `--yes` it only
prints what it would do:

~~~
noctua apply examples/rules.yml
noctua apply examples/rules.yml --yes
~~~

## How it decides

- Rules are read from top to bottom and the first match wins. Only rules that
  go the same way as the packet are looked at.
- If nothing matches, incoming packets are dropped and outgoing packets are
  allowed.
- Replies to connections the machine started are allowed
  (`ct state established,related`), otherwise its own web browsing would break.
- Local traffic on the loopback interface is allowed in both directions.
- `apply` is a dry run unless `--yes` is given, and the ruleset goes through
  `nft -c` first, so a broken ruleset is never loaded.

## Logging

A rule with `log: true` writes a line starting with `noctua:` to the kernel
log whenever it matches, before the packet is accepted or dropped. On Linux
you can read it with `journalctl -k` or `dmesg`. A busy rule can fill the
logs quickly, so use it on rules you care about.

## Limits

- Traffic that is not matched by any rule is not logged.
- No forwarding chain, so it is meant for a single machine and not a router.

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