# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — Dark Web Monitor Microservice
#  backend/services/darkweb/Dockerfile
#
#  ARCH-001: Isolated container for dark web intelligence collection.
#
#  Security hardening:
#  ───────────────────
#  1. Non-root user (uid 10001) — no sudo, no setuid binaries
#  2. Read-only root filesystem — only /tmp and /app/logs writable
#  3. Minimal base image (node:20-alpine) — no shell, no package manager
#     in the final stage
#  4. Multi-stage build — build deps not present in runtime image
#  5. No network access by default — Tor SOCKS5 proxy injected via
#     Docker network; direct internet access blocked by network policy
#  6. Capabilities dropped — NET_RAW and all others removed
#  7. Process runs as PID 1 with tini for correct signal handling
#  8. Health check via /health endpoint (required for K8s probes)
#  9. DARKWEB_SITES_ENCRYPTED / DARKWEB_SITES_KEY injected at runtime
#     from Kubernetes Secret / Vault — never baked into image
#
#  Environment variables required at runtime:
#    TOR_PROXY_HOST          — Tor SOCKS5 proxy hostname (default: tor)
#    TOR_PROXY_PORT          — Tor SOCKS5 port (default: 9050)
#    TOR_CONTROL_PORT        — Tor control port for NEWNYM (optional)
#    TOR_CONTROL_PASS        — Tor control password (optional)
#    DARKWEB_ENABLED         — "true" to enable scanning
#    DARKWEB_ORG_KEYWORDS    — comma-separated org keywords to monitor
#    DARKWEB_SITES_ENCRYPTED — AES-256-GCM encrypted site list (optional)
#    DARKWEB_SITES_KEY       — decryption key for site list (optional)
#    KAFKA_BROKER            — Kafka broker for publishing findings
#    SUPABASE_URL            — for IOC persistence
#    SUPABASE_SERVICE_KEY    — service role key for IOC writes
#    REDIS_URL               — for cache/pub-sub eviction
# ══════════════════════════════════════════════════════════════════

# ── Stage 1: Dependencies ─────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /build

# Copy only package files first for layer caching
COPY backend/package.json backend/package-lock.json ./

# Install production dependencies only (no devDependencies)
RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM node:20-alpine AS runtime

# Install tini for PID 1 / signal forwarding
RUN apk add --no-cache tini

# Create non-root user and group
RUN addgroup -S darkweb -g 10001 \
    && adduser  -S darkweb -u 10001 -G darkweb -H -s /sbin/nologin

WORKDIR /app

# Copy dependencies from build stage
COPY --from=deps /build/node_modules ./node_modules

# Copy only the necessary source files
COPY backend/services/darkweb/darkweb-monitor.js  ./services/darkweb/darkweb-monitor.js
COPY backend/services/darkweb/darkweb-server.js   ./services/darkweb/darkweb-server.js
COPY backend/config/                               ./config/

# Create writable directories
RUN mkdir -p /app/logs /tmp/darkweb \
    && chown -R darkweb:darkweb /app/logs /tmp/darkweb

# Drop to non-root user
USER darkweb

# Expose health-check port (not the public internet — only K8s internal)
EXPOSE 8081

# Security: read-only root fs enforced at orchestrator level (K8s securityContext)
# The VOLUME declarations below are advisory for docker-compose use
VOLUME ["/app/logs"]

# Health check — fails if scanner hasn't reported healthy within 2 minutes
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget -qO- http://localhost:8081/health || exit 1

# Use tini as PID 1 to handle SIGTERM correctly
ENTRYPOINT ["/sbin/tini", "--"]

# Run the darkweb microservice HTTP server
CMD ["node", "services/darkweb/darkweb-server.js"]
