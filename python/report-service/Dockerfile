# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — Report Generation Service Dockerfile
#  python/report-service/Dockerfile
# ══════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS base

RUN groupadd -r reports && useradd -r -g reports -u 1001 reports

WORKDIR /app

# WeasyPrint + ReportLab system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libpango-1.0-0 \
      libpangocairo-1.0-0 \
      libcairo2 \
      libgdk-pixbuf2.0-0 \
      libffi-dev \
      shared-mime-info \
      fonts-liberation \
      fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

FROM base AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

FROM deps AS production
COPY --chown=reports:reports . .
RUN mkdir -p /app/reports && chown reports:reports /app/reports

USER reports
EXPOSE 5002

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5002/health')"

CMD ["uvicorn", "report_service:app", "--host", "0.0.0.0", "--port", "5002", \
     "--workers", "1", "--log-level", "info"]
