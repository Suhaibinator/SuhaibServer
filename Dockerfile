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

# Copy a default config file into the container (optional but convenient).
# This allows the container to run even if the user doesn't provide a config.
COPY config.example.yaml /etc/suhaibserver/config.yaml

# If the app listens on 443 (typical for TLS), expose it
EXPOSE 443

# By default, run SuhaibServer with the config file we copied.
# Users can override this path at runtime if needed.
CMD ["/usr/local/bin/SuhaibServer", "/etc/suhaibserver/config.yaml"]
