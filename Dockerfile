# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o honeybee-node ./cmd/node

# Final stage
FROM alpine:latest

# Install ca-certificates for TLS
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 honeybee && \
    adduser -D -u 1000 -G honeybee honeybee

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/honeybee-node .

# Copy default config
COPY configs/config.yaml configs/

# Create directories with correct permissions
RUN mkdir -p /app/certs /app/logs && \
    chown -R honeybee:honeybee /app

# Switch to non-root user
USER honeybee

# Expose port (if needed)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD pgrep honeybee-node || exit 1

# Run
ENTRYPOINT ["./honeybee-node"]
CMD ["-config", "configs/config.yaml"]

