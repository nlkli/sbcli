# sbcli

[Русский](README.md) | English

A small, fast command-line client for the [sing-box](https://github.com/SagerNet/sing-box) Clash API, with a built-in converter between proxy share links and sing-box outbounds.

Tested with **sing-box 1.14.4**.

![interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/interactive-demo.gif)

## Features

- Inspect and control proxies, groups, rules and connections
- Select group members, test proxy and group delay
- Convert proxy links to sing-box outbounds and back
- Interactive TUI: switch proxies, live delay and connection monitoring, close connections, filter tables

## Install

**Homebrew** ([formula](https://github.com/nlkli/homebrew-tap/blob/main/Formula/sbcli.rb))

```sh
brew install nlkli/tap/sbcli
```

**Download a release**

- [macOS (Apple Silicon)](https://github.com/nlkli/sbcli/releases/latest/download/sbcli-macos-arm64.zip)
- [Linux (x86_64)](https://github.com/nlkli/sbcli/releases/latest/download/sbcli-linux-amd64.zip)

**Build from source**

```sh
git clone https://github.com/nlkli/sbcli
cd sbcli
cargo b -r && ./target/release/sbcli -h
```

## Usage

sbcli talks to sing-box through its [Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/) (available since sing-box 1.8.0). Enable it in your sing-box config first:

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090"
    }
  }
}
```

| Option | Description |
|---|---|
| `-a, --api <URL>` | Controller URL (env `SINGBOX_CLASH_API`, default `http://127.0.0.1:9090`) |
| `-T, --token <TOKEN>` | Bearer token, if you set a `secret` in the config |

If sing-box runs locally on the default `http://127.0.0.1:9090` and has no `secret`, you don't need to pass any of these.

### Interactive mode

```sh
sbcli -i
sbcli -a http://127.0.0.1:9090 -T <TOKEN> -i
```

A terminal UI for managing sing-box without retyping commands:

- **Switch proxies**: pick the active member of any selector group
- **Live delay**: watch proxy and group latency in real time
- **Live connections**: follow connections as they open and close
- **Close connections**: drop one or all
- **Filter**: type to narrow down any table

![server-interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/server-interactive-demo.gif)

### All options

Short flags can be combined, e.g. `-lZ`.

```text
Proxies
  -P, --proxies                     List proxies
  -p, --proxy <NAME>                Show a proxy
  -s, --select <GROUP> <NAME>       Select a group member
  -d, --proxy-delay <NAME>          Test a proxy delay
Groups
  -G, --groups                      List groups
  -g, --group <NAME>                Show a group
  -D, --group-delay <NAME>          Test a group delay
Delay test
  -u, --url <URL>                   Probe URL [default: gstatic 204]
  -t, --timeout <MS>                Probe timeout [default: 5000]
Rules and connections
  -R, --rules                       List rules
  -C, --connections                 List connections
  -c, --close-connection <ID>       Close a connection
  -X, --close-all-connections       Close all connections
DNS
  -q, --dns-query <NAME> <TYPE>     Query DNS (A, AAAA, TXT, ...)
  -N, --flush-dns-cache             Flush DNS cache
  -F, --flush-fakeip-cache          Flush fake-IP cache
Link converter
  -l, --links-to-outbounds <SRC>    Convert links to outbounds
  -L, --links-from-outbounds <SRC>  Convert outbounds to links
  -Z, --uuid-tag                    Rewrite tags to random UUIDs
  -o, --output <DST>                Output file for the preceding -l/-L
```

### Examples

Show a group:

```sh
$ sbcli -g proxy
{
  "type": "Selector",
  "name": "proxy",
  "now": "msk2-ss-hy2",
  "all": [
    "msk2-tor-hy2",
    "msk2-ss-hy2",
    "msk2-tor-vless",
    "msk2-ss-vless"
  ]
}
```

Switch the `out` group between members:

```sh
sbcli -s out direct
sbcli -s out proxy
```

Convert links to outbounds with random UUID tags, saved to a file:

```sh
sbcli -lZ links.txt -o outbounds.json
```

Convert outbounds back to links:

```sh
sbcli -L outbounds.json -o links.txt
```

## TUN client guide

A full setup: your links, sing-box in TUN mode, sbcli on top.
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

sbcli prints a JSON array, but sing-box expects an object with an `outbounds` key. Wrap it with `jq`:

```sh
mkdir -p conf
sbcli -l links.txt | jq '{outbounds: .}' > conf/01-outbounds.json
```

### 3. Add the TUN config

Save as `conf/02-config.json`. The `proxy` selector must list the tags from your links.

```json
{
    "experimental": {
        "cache_file": { "enabled": true },
        "clash_api": { "external_controller": "127.0.0.1:9090" }
    },
    "dns": {
        "servers": [
            {
                "tag": "remote",
                "type": "https",
                "server": "1.1.1.1",
                "detour": "proxy"
            },
            {
                "tag": "local",
                "type": "udp",
                "server": "77.88.8.8"
            }
        ],
        "rules": [
            {
                "domain_suffix": [".ru", ".su", ".рф"],
                "action": "route",
                "server": "local"
            }
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
            "auto_route": true,
            "strict_route": true
        }
    ],
    "outbounds": [
        { "type": "direct", "tag": "direct" },
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": [
                "node-vless",
                "node-hy2",
                "node-ss",
                "node-trojan"
            ],
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
            {
                "domain_suffix": [".ru", ".su", ".рф"],
                "outbound": "direct"
            }
        ],
        "final": "out"
    }
}
```

This config sends `.ru`, `.su` and `.рф` domains directly and everything else through the proxy. Adjust the suffixes and the `local` DNS server for your region.

Prefer a ready-made setup? Take [my personal config for Russia](https://github.com/nlkli/dotfiles/blob/main/config/sing-box.json) and replace the tags in the `proxy` selector with the tags from your links.

### 4. Run

`-C` loads and merges all JSON files in the directory:

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

### DNS troubleshooting

If sites don't load or DNS leaks, check your system DNS. It **must not point to your router** (e.g. `192.168.1.1`). Router addresses are local, so those queries skip the tunnel and sing-box never sees them. Set a public DNS server instead (e.g. `1.1.1.1`): its queries go through the TUN interface, where sing-box intercepts and routes them by your DNS rules.

On macOS (replace `Wi-Fi` with your network service, see `networksetup -listallnetworkservices`):

```sh
macos-dns-set() {
    sudo networksetup -setdnsservers Wi-Fi 1.1.1.1
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder
}

macos-dns-clear() {
    sudo networksetup -setdnsservers Wi-Fi empty
}
```

Run `macos-dns-set` before connecting, and `macos-dns-clear` to go back to the default (router) DNS.

## Configuration

- `SINGBOX_CLASH_API`: default controller URL when `-a` is not given.

---

sing-box singbox clash-api cli tui rust proxy proxy-manager proxy-client link-converter tun vless hysteria2 shadowsocks trojan socks5 dns selector terminal networking
