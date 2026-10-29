# XNode

## Install

Linux & macOS

```text
curl -fsSL https://raw.githubusercontent.com/KilluaAoki/XNode/main/script/install.sh | sudo bash
```

Windows

```text
irm https://raw.githubusercontent.com/KilluaAoki/XNode/main/script/install.ps1 | iex
```

Docker

```text
docker run -d --restart=always --network=host -e apiHost=https://panel.example.com -e apiKey=TOKEN -e nodeID=1 -e nodeType=vless ghcr.io/killuaaoki/xnode:latest
```

## Build

```text
go build -o xnode -trimpath -ldflags "-s -w" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" .
```

## Acknowledgements

This project draws on the following projects:

- [cedar2025/Xboard-Node](https://github.com/cedar2025/Xboard-Node)
- [wyx2685/V2bX](https://github.com/wyx2685/V2bX)
- [wyx2685/v2node](https://github.com/wyx2685/v2node)
