# Build portpilot as a static binary.
# Usage: docker build -t portpilot . && docker cp $(docker create portpilot):/portpilot .
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /portpilot .

FROM scratch
COPY --from=builder /portpilot /portpilot
ENTRYPOINT ["/portpilot"]
