# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — Alert Clustering Service Dockerfile
#  python/clustering/Dockerfile
# ══════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS base

# Security: run as non-root
RUN groupadd -r clustering && useradd -r -g clustering -u 1001 clustering

WORKDIR /app

# Install system deps for scipy/hdbscan native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ──────────────────────────────────────────────────
FROM base AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# ── Final image ───────────────────────────────────────────────────
FROM deps AS production
COPY --chown=clustering:clustering . .

RUN mkdir -p /app/models && chown clustering:clustering /app/models

USER clustering

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8002/health')"

CMD ["uvicorn", "alert_clustering:app", "--host", "0.0.0.0", "--port", "8002", \
     "--workers", "2", "--log-level", "info"]
