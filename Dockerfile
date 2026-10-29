FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0
WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,target=. \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -tags "with_quic with_utls with_wireguard with_acme with_clash_api" \
    -ldflags "-X main.version=${VERSION} -s -w -buildid=" \
    -o /out/xnode .

FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir /etc/xnode
ENV TZ=Asia/Shanghai
WORKDIR /etc/xnode
COPY --from=builder /out/xnode /usr/local/bin/xnode
ENTRYPOINT ["xnode"]
CMD ["server", "-c", "/etc/xnode/config.yml"]
