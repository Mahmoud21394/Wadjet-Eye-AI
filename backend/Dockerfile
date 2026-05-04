# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — Backend Dockerfile
#  backend/Dockerfile
#
#  Multi-stage build:
#    deps        — install all npm dependencies
#    production  — lean runtime image (no devDeps, no build tools)
#
#  Build:  docker build -t wadjet-eye/backend:latest ./backend
#  Run:    docker run -p 4000:4000 --env-file .env wadjet-eye/backend:latest
# ══════════════════════════════════════════════════════════════════

# ── Stage 1: dependency installation ─────────────────────────────
FROM node:20-alpine AS deps

RUN apk add --no-cache python3 make g++   # for native addons (bcrypt, canvas…)

WORKDIR /app

# Copy manifests first for layer caching
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# ── Stage 2: production image ─────────────────────────────────────
FROM node:20-alpine AS production

# Security hardening
RUN apk add --no-cache tini curl \
 && addgroup -S wadjet \
 && adduser  -S -G wadjet -u 1001 wadjet

WORKDIR /app

# Copy pruned node_modules from deps stage
COPY --from=deps --chown=wadjet:wadjet /app/node_modules ./node_modules

# Copy application source (exclude dev artifacts via .dockerignore)
COPY --chown=wadjet:wadjet . .

# Create required runtime directories
RUN mkdir -p /app/logs /app/tmp \
 && chown -R wadjet:wadjet /app/logs /app/tmp

USER wadjet

EXPOSE 4000

# Use tini as PID 1 to forward signals correctly
ENTRYPOINT ["/sbin/tini", "--"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -fsS http://localhost:4000/health | grep -q '"status":"ok"' || exit 1

CMD ["node", "server.js"]
