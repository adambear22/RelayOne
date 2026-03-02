FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o /out/nodepass-agent ./cmd/agent

FROM alpine:3.20
RUN adduser -D -H -s /sbin/nologin nodepass
USER nodepass
WORKDIR /var/lib/nodepass-agent
COPY --from=builder /out/nodepass-agent /usr/local/bin/nodepass-agent
ENTRYPOINT ["/usr/local/bin/nodepass-agent"]
