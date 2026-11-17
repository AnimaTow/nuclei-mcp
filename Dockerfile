# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for go modules and HTTPS)
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go.mod (this fork ships without a committed go.sum; build with -mod=mod)
COPY go.mod ./
ENV GOFLAGS=-mod=mod
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -a -installsuffix cgo -o nuclei-mcp ./cmd/nuclei-mcp

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S nuclei && \
    adduser -u 1001 -S nuclei -G nuclei

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/nuclei-mcp .

# Copy configuration, scope allowlist and templates
COPY --from=builder /app/config.yaml .
COPY --from=builder /app/scope.json .
COPY --from=builder /app/nuclei-templates ./nuclei-templates/
COPY --from=builder /app/templates ./templates/

# Change ownership to nuclei user
RUN mkdir -p /app/logs && chown -R nuclei:nuclei /app

# Switch to non-root user
USER nuclei

# Scope allowlist location (override by mounting a scope.json here, or set NUCLEI_ALLOW)
ENV NUCLEI_SCOPE=/app/scope.json

# Expose MCP HTTP port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgrep nuclei-mcp || exit 1

# Run the MCP server; default to streamable-http transport (override with "stdio")
ENTRYPOINT ["./nuclei-mcp"]
CMD ["http"]
