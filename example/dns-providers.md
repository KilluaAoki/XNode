# DNS Providers

Used by `cert_config.cert_mode: "dns"` for ACME DNS-01.

```yaml
cert_config:
  cert_mode: "dns"
  dns_provider: "cloudflare"
  dns_env:
    CLOUDFLARE_DNS_API_TOKEN: "xxx"
```

| provider   | aliases | env                                                                                         |
| ---------- | ------- | ------------------------------------------------------------------------------------------- |
| cloudflare | cf      | `CLOUDFLARE_DNS_API_TOKEN` (or `CF_DNS_API_TOKEN`, `CF_API_TOKEN`, `CLOUDFLARE_API_TOKEN`) |
