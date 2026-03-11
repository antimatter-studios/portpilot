# portpilot

Automatic port detection and reverse proxy for containers. Monitors `/proc/net/tcp` for new listening ports and dynamically proxies them — like VS Code's port forwarding, but standalone.

## Install

Download a binary from [Releases](https://github.com/antimatter-studios/portpilot/releases), or build from source:

```bash
go install github.com/antimatter-studios/portpilot@latest
```

## Usage

```bash
# Run a child process and auto-proxy any ports it opens
portpilot --listen :8080 -- python -m http.server 3000

# Access the child's server at /proxy/3000/
curl http://localhost:8080/proxy/3000/

# Ignore specific ports
portpilot --listen :8080 --ignore 9229,5432 -- node server.js

# Set a base path prefix (useful behind a reverse proxy)
portpilot --listen :8080 --base-path /ws/abc123 -- ttyd --port 7682 bash
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:7681` | Address to listen on |
| `--base-path` | `$PROXY_BASE_PATH` | Base URL path prefix |
| `--scan-interval` | `2s` | How often to scan for new ports |
| `--ignore` | *(listen port)* | Comma-separated ports to skip |
| `--version` | | Print version and exit |

Everything after `--` is treated as the child command to run.

## How it works

1. Starts the child process (if provided)
2. Every `scan-interval`, reads `/proc/net/tcp` and `/proc/net/tcp6` for sockets in LISTEN state (`0A`)
3. For each new port detected, creates a reverse proxy at `/proxy/{port}/`
4. When a port stops listening, removes the proxy
5. Sets `X-Forwarded-Prefix` header on proxied requests

## Docker

```dockerfile
# Multi-stage: install portpilot in a builder, copy the binary
FROM golang:1.25-alpine AS portpilot
RUN CGO_ENABLED=0 go install github.com/antimatter-studios/portpilot@latest

FROM your-base-image
COPY --from=portpilot /go/bin/portpilot /usr/local/bin/portpilot
```

## License

MIT
