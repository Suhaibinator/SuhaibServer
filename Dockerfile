# syntax=docker/dockerfile:1

###
# 1) Builder stage
###
FROM golang:1.24-alpine AS builder

# Install any necessary build tools. For example, if you need Git:
# RUN apk add --no-cache git

WORKDIR /app

# Copy go.mod and go.sum (if you have them) and download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of your application source
COPY . .

# Build your Go application; adjust main.go or the build command as needed.
RUN go build -o /go-bin/app

###
# 2) Final runtime stage
###
FROM alpine:3.18 AS final

# Copy the compiled binary from the builder stage into this minimal image
COPY --from=builder /go-bin/app /usr/local/bin/app

# If your app listens on port 8080 by default, expose it:
EXPOSE 8080

# Run the binary
CMD ["/usr/local/bin/app"]
