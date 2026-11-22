# sbcli

A small, fast command-line client for the [sing-box](https://github.com/SagerNet/sing-box) Clash API, with a built-in converter between proxy share links and sing-box outbounds.

![interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/interactive-demo.gif)

## Features

- Inspect and control proxies, groups, rules and connections
- Select group members (manually or randomly) and test proxy/group delay
- Convert proxy links to sing-box outbounds and back
- Interactive TUI: switch proxies, live delay and connection monitoring, close connections, filter tables

### Build

```sh
cargo build --release
./target/release/sbcli -h
```

### Homebrew

[Formula](https://github.com/nlkli/homebrew-tap/blob/main/Formula/sbcli.rb)

```sh
brew install nlkli/tap/sbcli
```
### Release Download

- [macOS (Apple Silicon)](https://github.com/nlkli/sbcli/releases/latest/download/sbcli-macos-arm64.zip)
- [Linux (x86_64)](https://github.com/nlkli/sbcli/releases/latest/download/sbcli-linux-amd64.zip)

### Usage

| Option | Description |
|---|---|
| `-a, --api <URL>` | Controller URL (env `SINGBOX_CLASH_API`, default `http://127.0.0.1:9090`) |
| `-T, --token <TOKEN>` | Bearer token (secret) |
| `-i, --interactive` | Interactive mode |

## Interactive mode

```sh
sbcli -i
sbcli -a http://127.0.0.1:9090 -T <TOKEN> -i
```

A terminal UI for managing sing-box without retyping commands:

- **Switch proxies**: pick the active member of any selector group
- **Live delay monitoring**: watch proxy and group latency change in real time
- **Live connections**: follow active connections as they open and close
- **Close connections**: drop a single connection or all of them
- **Filter**: narrow down any table by typing a search string

### 800+ outbounds demo

![server-interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/server-interactive-demo.gif)

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

## Tun client guide

Docs: [sing-box configuration](https://sing-box.sagernet.org/configuration/) · [TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)

### 1. Prepare links

Save one link per line to `links.txt`. The part after `#` becomes the outbound tag.

```
vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04&sid=6ba85179e30d4fc2&type=tcp#node-vless
hysteria2://mypassword@203.0.113.11:443?sni=www.example.com#node-hy2
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@203.0.113.12:8388#node-ss
trojan://mypassword@203.0.113.13:443?sni=www.example.com#node-trojan
```

### 2. Convert to outbounds

`sbcli` prints a JSON array, but sing-box needs an object with an `outbounds` key. Wrap it with `jq`:

```sh
mkdir -p conf
sbcli -l links.txt | jq '{outbounds: .}' > conf/01-outbounds.json
```

### 3. Add the TUN config

Save as `conf/02-config.json`. The `proxy` selector lists the tags from your links.

```json
{
    "experimental": {
        "cache_file": { "enabled": true },
        "clash_api": { "external_controller": "127.0.0.1:9090" }
    },
    "dns": {
        "servers": [
            { "tag": "remote", "type": "https", "server": "1.1.1.1", "detour": "proxy" },
            { "tag": "local", "type": "udp", "server": "77.88.8.8" }
        ],
        "rules": [
            { "domain_suffix": [".ru", ".su", ".рф"], "action": "route", "server": "local" }
        ],
        "final": "remote",
        "strategy": "prefer_ipv4",
        "optimistic": true
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1280,
            "auto_route": true,
            "strict_route": true
        }
    ],
    "outbounds": [
        { "type": "direct", "tag": "direct" },
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["node-vless", "node-hy2", "node-ss", "node-trojan"],
            "interrupt_exist_connections": true
        },
        {
            "type": "selector",
            "tag": "out",
            "outbounds": ["direct", "proxy"],
            "interrupt_exist_connections": true
        }
    ],
    "route": {
        "auto_detect_interface": true,
        "default_domain_resolver": "local",
        "rules": [
            { "action": "sniff" },
            { "protocol": "dns", "action": "hijack-dns" },
            { "ip_is_private": true, "outbound": "direct" },
            { "domain_suffix": [".ru", ".su", ".рф"], "outbound": "direct" }
        ],
        "final": "out"
    }
}
```

### 4. Run

`-C` loads and merges all JSON files from the directory:

```sh
sudo sing-box run -C conf
```

### 5. Control with sbcli

```sh
sbcli -g proxy               # show the group
sbcli -s proxy node-hy2      # pick an outbound
sbcli -s out direct          # bypass the proxy
sbcli -s out proxy           # route through the proxy
sbcli -i                     # interactive mode
```

---

sing-box singbox clash-api cli tui rust proxy proxy-manager proxy-client link-converter tun vless hysteria2 shadowsocks trojan socks5 dns selector terminal networking
