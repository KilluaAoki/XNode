# Custom Outbounds

## Quick Example

```json
{
  "custom_outbounds": [
    {
      "tag": "warp",
      "protocol": "wireguard",
      "settings": {
        "peers": [{ "address": "162.159.195.1" }],
        "private_key": "aMzA..."
      }
    },
    {
      "tag": "us-proxy",
      "protocol": "socks",
      "settings": { "servers": [{ "address": "1.2.3.4", "port": 1080 }] },
      "proxy_tag": "warp"
    }
  ]
}
```

## Supported Protocols

| Protocol    | Xray | Sing-box |
| ----------- | ---- | -------- |
| vmess       | ✓    | ✓        |
| vless       | ✓    | ✓        |
| trojan      | ✓    | ✓        |
| shadowsocks | ✓    | ✓        |
| socks       | ✓    | ✓        |
| http        | ✓    | ✓        |
| wireguard   | ✓    | ✓        |
| tuic        | ✗    | ✓        |
| hysteria2   | ✗    | ✓        |
| anytls      | ✗    | ✓        |
| naive       | ✗    | ✓        |
| mieru       | ✗    | ✓        |

## Core Fields

| Field       | Required | Description                                    |
| ----------- | -------- | ---------------------------------------------- |
| `tag`       | ✓        | Outbound tag, referenced in routes             |
| `protocol`  | ✓        | Protocol type                                  |
| `settings`  | ✓        | Protocol-specific configuration                |
| `proxy_tag` | ✗        | Chain to another outbound (references its tag) |

## Outgoing Address

Outbounds in `kernel.custom_config` are written in the kernel's native format. One tagged `direct` replaces the built-in direct outbound and stays the default.

```yaml
# kernel.custom_config for xray
outbounds:
  - { tag: "direct", protocol: "freedom", sendThrough: "203.0.113.2" }
```

```yaml
# kernel.custom_config for sing-box
outbounds:
  - { tag: "direct", type: "direct", inet4_bind_address: "203.0.113.2" }
```

## Best Practices

- **Prefer** `custom_outbounds`: panel-managed, cross-kernel compatible
- **Use** `kernel.custom_config` only: when native fields are needed
