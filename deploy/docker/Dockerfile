# ── Stage 1: Build Go binary ─────────────────────────────────────────────────
FROM golang:1.26.3-alpine AS go-builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /bin/1sec \
    ./cmd/1sec

# ── Stage 2: Build Rust engine (optional) ────────────────────────────────────
FROM rust:1.94-alpine AS rust-builder

RUN apk add --no-cache musl-dev libpcap-dev

WORKDIR /build

COPY rust/1sec-engine/ ./

# Build without pcap by default (add --features pcap-capture for packet capture)
RUN cargo build --release --no-default-features \
    && strip target/release/1sec-engine

# ── Stage 3: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.21

# OCI image labels
LABEL org.opencontainers.image.title="1SEC" \
      org.opencontainers.image.description="All-in-one cybersecurity defense platform" \
      org.opencontainers.image.url="https://1-sec.dev" \
      org.opencontainers.image.source="https://github.com/simpleending/1-sec" \
      org.opencontainers.image.vendor="1SEC" \
      org.opencontainers.image.licenses="AGPL-3.0"

RUN apk add --no-cache ca-certificates tzdata libpcap \
    && adduser -D -u 1000 onesec

COPY --from=go-builder /bin/1sec /bin/1sec
COPY --from=rust-builder /build/target/release/1sec-engine /bin/1sec-engine

# Default config — override by mounting /etc/1sec/config.yaml
COPY configs/default.yaml /etc/1sec/config.yaml

# Create data directory
RUN mkdir -p /data/nats && chown onesec:onesec /data/nats

WORKDIR /

USER onesec

# API port
EXPOSE 1780
# NATS embedded port
EXPOSE 4222
# Syslog ingestion (UDP/TCP)
EXPOSE 1514/udp
EXPOSE 1514/tcp

# Persist NATS JetStream data
VOLUME ["/data/nats"]

ENTRYPOINT ["/bin/1sec"]
CMD ["up", "--config", "/etc/1sec/config.yaml"]
