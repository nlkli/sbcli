# sbcli

Русский | [English](README.en.md)

Небольшой быстрый консольный клиент для Clash API [sing-box](https://github.com/SagerNet/sing-box) со встроенным конвертером между ссылками на прокси и outbound-ами sing-box.

Проверено на **sing-box 1.14.4**.

![interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/interactive-demo.gif)

## Возможности

- Просмотр и управление прокси, группами, правилами и соединениями
- Выбор активного прокси в группе, проверка задержки прокси и групп
- Конвертация ссылок в outbound-ы sing-box и обратно
- Интерактивный TUI: переключение прокси, задержка и соединения в реальном времени, закрытие соединений, фильтрация таблиц

## Установка

**Homebrew** ([формула](https://github.com/nlkli/homebrew-tap/blob/main/Formula/sbcli.rb))

```sh
brew install nlkli/tap/sbcli
```

**Готовые релизы**

- [macOS (Apple Silicon)](https://github.com/nlkli/sbcli/releases/latest/download/sbcli-macos-arm64.zip)
- [Linux (x86_64)](https://github.com/nlkli/sbcli/releases/latest/download/sbcli-linux-amd64.zip)

**Сборка из исходников**

```sh
git clone https://github.com/nlkli/sbcli
cd sbcli
cargo b -r && ./target/release/sbcli -h
```

## Использование

sbcli работает с sing-box через [Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/) (доступен с sing-box 1.8.0). Сначала включите его в конфиге sing-box:

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090"
    }
  }
}
```

| Опция | Описание |
|---|---|
| `-a, --api <URL>` | Адрес контроллера (переменная `SINGBOX_CLASH_API`, по умолчанию `http://127.0.0.1:9090`) |
| `-T, --token <TOKEN>` | Bearer-токен, если в конфиге задан `secret` |

Если sing-box запущен локально на адресе по умолчанию `http://127.0.0.1:9090` и без `secret`, указывать ничего не нужно.

### Интерактивный режим

```sh
sbcli -i
sbcli -a http://127.0.0.1:9090 -T <TOKEN> -i
```

Терминальный интерфейс, чтобы не вводить команды вручную:

- **Переключение прокси**: выбор активного элемента любой selector-группы
- **Задержка в реальном времени**: пинг прокси и групп обновляется на лету
- **Соединения в реальном времени**: видно, как они открываются и закрываются
- **Закрытие соединений**: одного или всех сразу
- **Фильтр**: введите строку, чтобы отфильтровать любую таблицу

![server-interactive-demo-gif](https://github.com/nlkli/assetsrepo/blob/main/sbcli.demo/server-interactive-demo.gif)

### Все опции

Короткие флаги можно объединять, например `-lZ`. Ниже вывод `sbcli -h` (на английском).

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

### Примеры

Показать группу:

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

Переключить группу `out`:

```sh
sbcli -s out direct
sbcli -s out proxy
```

Конвертировать ссылки в outbound-ы со случайными UUID вместо тегов и сохранить в файл:

```sh
sbcli -lZ links.txt -o outbounds.json
```

Конвертировать outbound-ы обратно в ссылки:

```sh
sbcli -L outbounds.json -o links.txt
```

## Гайд: TUN-клиент

Полная настройка: ваши ссылки, sing-box в режиме TUN и sbcli для управления.
Документация: [конфигурация sing-box](https://sing-box.sagernet.org/configuration/) · [TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)

### 1. Подготовьте ссылки

Сохраните ссылки в `links.txt`, по одной на строку. Часть после `#` станет тегом outbound-а.

```
vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04&sid=6ba85179e30d4fc2&type=tcp#node-vless
hysteria2://mypassword@203.0.113.11:443?sni=www.example.com#node-hy2
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@203.0.113.12:8388#node-ss
trojan://mypassword@203.0.113.13:443?sni=www.example.com#node-trojan
```

### 2. Сконвертируйте в outbound-ы

sbcli выводит JSON-массив, а sing-box ожидает объект с ключом `outbounds`. Оберните вывод через `jq`:

```sh
mkdir -p conf
sbcli -l links.txt | jq '{outbounds: .}' > conf/01-outbounds.json
```

### 3. Добавьте конфиг TUN

Сохраните как `conf/02-config.json`. В селекторе `proxy` должны быть теги из ваших ссылок.

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

Этот конфиг отправляет домены `.ru`, `.su` и `.рф` напрямую, а всё остальное через прокси. При необходимости поменяйте суффиксы и DNS-сервер `local` под свой регион.

Нужен готовый вариант? Возьмите [мой личный конфиг для России](https://github.com/nlkli/dotfiles/blob/main/config/sing-box.json) и замените теги в селекторе `proxy` на теги из ваших ссылок.

### 4. Запустите

`-C` загружает и объединяет все JSON-файлы из каталога:

```sh
sudo sing-box run -C conf
```

### 5. Управляйте через sbcli

```sh
sbcli -g proxy               # показать группу
sbcli -s proxy node-hy2      # выбрать outbound
sbcli -s out direct          # напрямую, без прокси
sbcli -s out proxy           # через прокси
sbcli -i                     # интерактивный режим
```

### DNS: если что-то не работает

Если сайты не открываются или DNS утекает, проверьте системный DNS. Он **не должен указывать на роутер** (например, `192.168.1.1`). Адрес роутера локальный, поэтому такие запросы идут мимо туннеля и sing-box их не видит. Укажите вместо него публичный DNS (например, `1.1.1.1`): запросы пойдут через интерфейс TUN, где sing-box перехватит их и обработает по вашим DNS-правилам.

На macOS (замените `Wi-Fi` на имя вашего сетевого сервиса, список: `networksetup -listallnetworkservices`):

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

Запустите `macos-dns-set` перед подключением, а `macos-dns-clear` вернёт DNS по умолчанию (от роутера).

## Конфигурация

- `SINGBOX_CLASH_API`: адрес контроллера по умолчанию, если не указан `-a`.

---

sing-box singbox clash-api cli tui rust proxy proxy-manager proxy-client link-converter tun vless hysteria2 shadowsocks trojan socks5 dns selector terminal networking
