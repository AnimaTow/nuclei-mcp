#!/usr/bin/env sh
# Startet den nuclei-MCP (streamable-http) als Container, nur lokal gebunden.
# Pruefumfang (scope): eigene scope.json read-only hineinmounten ODER NUCLEI_ALLOW setzen.
# Ohne gueltigen Scope laesst der Server nur 127.0.0.1/32 zu (fail-closed).
set -eu

IMAGE="${IMAGE:-nuclei-mcp:0.1}"
NAME="${NAME:-nuclei-mcp}"
HOST_BIND="${HOST_BIND:-127.0.0.1}"   # nur lokal erreichbar
HOST_PORT="${HOST_PORT:-8792}"
SCOPE_FILE="${SCOPE_FILE:-$(pwd)/scope.json}"  # eigene Allowlist

docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p "${HOST_BIND}:${HOST_PORT}:3000" \
  -e NUCLEI_MCP_SERVER_HOST=0.0.0.0 \
  -e NUCLEI_SCOPE=/app/scope.json \
  -v "${SCOPE_FILE}:/app/scope.json:ro" \
  "$IMAGE" http

echo "nuclei-MCP laeuft auf http://${HOST_BIND}:${HOST_PORT}/mcp (Scope: ${SCOPE_FILE})"
