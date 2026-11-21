# sbcli

A small, fast command-line client for the [sing-box](https://github.com/SagerNet/sing-box) Clash API, with a built-in converter between proxy share links and sing-box outbounds.

![interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/interactive-demo.gif)

## Features

- Inspect and control proxies, groups, rules and connections
- Select group members (manually or randomly) and test proxy/group delay
- Query DNS, flush DNS / fake-IP caches
- Convert proxy links to sing-box outbounds and back
- Interactive mode with full control

## Build

```sh
cargo build --release
./target/release/sbcli -h
```

### Usage

| Option | Description |
|---|---|
| `-a, --api <URL>` | Controller URL (env `SINGBOX_CLASH_API`, default `http://127.0.0.1:9090`) |
| `-T, --token <TOKEN>` | Bearer token (secret) |
| `-i, --interactive` | Interactive mode |

### Proxies and groups

| Option | Description |
|---|---|
| `-P, --proxies` | List proxies |
| `-p, --proxy <NAME>` | Show a proxy |
| `-G, --groups` | List groups |
| `-g, --group <NAME>` | Show a group |
| `-s, --select <GROUP> <NAME>` | Select a group member |
| `-S, --select-rand <GROUP>` | Select a random group member |
| `-d, --proxy-delay <NAME>` | Test a proxy's delay |
| `-D, --group-delay <NAME>` | Test a group's delay |
| `-u, --url <URL>` | Probe URL (default: gstatic 204) |
| `-t, --timeout <MS>` | Probe timeout (default: 5000) |

### Rules and connections

| Option | Description |
|---|---|
| `-R, --rules` | List rules |
| `-C, --connections` | List connections |
| `-c, --close-connection <ID>` | Close a connection |
| `-X, --close-all-connections` | Close all connections |

### DNS

| Option | Description |
|---|---|
| `-q, --dns-query <NAME> <TYPE>` | Query DNS (A, AAAA, TXT, ...) |
| `-N, --flush-dns-cache` | Flush DNS cache |
| `-F, --flush-fakeip-cache` | Flush fake-IP cache |

### Link converter

| Option | Description |
|---|---|
| `-l, --links-to-outbounds <SRC>` | Convert a file of links (one per line) to outbounds JSON |
| `-L, --links-from-outbounds <SRC>` | Convert an outbounds JSON file to links |
| `-Z, --uuid-tag` | Rewrite tags to random UUIDs |
| `-o, --output <DST>` | Output file for the preceding `-l` / `-L` (default: stdout) |

Short flags can be combined, e.g. `-lZ`.

## Examples

Show a group:

```sh
$ sbcli -a http://127.0.0.1:9090 -g proxy
{
  "type": "Selector",
  "name": "proxy",
  "now": "msk2-ss-hy2",
  "all": ["msk2-tor-hy2", "msk2-ss-hy2", "msk2-tor-vless", "msk2-ss-vless"]
}
```

Switch the `out` group between members:

```sh
sbcli -a http://127.0.0.1:9090 -s out direct
sbcli -a http://127.0.0.1:9090 -s out proxy
```

Convert links to outbounds with random UUID tags, saving to a file:

```sh
sbcli -lZ links.txt -o outbounds.json
```

Convert outbounds back to links:

```sh
sbcli -L outbounds.json -o links.txt
```

## Configuration

- `SINGBOX_CLASH_API`: default controller URL when `-a` is not given.

Your sing-box config must have the Clash API enabled (`experimental.clash_api`).

## Links

Source: <https://github.com/nlkli/sbcli>
