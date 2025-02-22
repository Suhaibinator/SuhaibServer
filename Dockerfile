# syntax=docker/dockerfile:1

###
# 1) Builder stage
###
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of your application source
COPY . .

# Build your Go application. Adjust paths as needed.
# For example, if your main.go is in /cmd, specify that path:
RUN go build -o /go-bin/SuhaibServer ./cmd/main.go

###
# 2) Final runtime stage
###
FROM alpine:3.18 AS final

# Copy the compiled binary from the builder stage into this minimal image
COPY --from=builder /go-bin/SuhaibServer /usr/local/bin/SuhaibServer

# We do NOT copy a config file here. Instead, we rely on Docker Swarm "configs"
# to provide /etc/suhaibserver/config.yaml at runtime.

# If the app listens on 443 (typical for TLS), expose it
EXPOSE 443

# By default, run SuhaibServer with the config file assumed to be at
# /etc/suhaibserver/config.yaml, which Docker Swarm mounts as a config.
CMD ["/usr/local/bin/SuhaibServer", "/etc/suhaibserver/config.yaml"]
