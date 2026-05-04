#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════════
 Wadjet-Eye AI — Alert Clustering Service (Phase 3 / Phase 7)
 python/clustering/alert_clustering.py

 FastAPI microservice that implements:
 • HDBSCAN alert clustering  (primary — handles noise well)
 • DBSCAN alert clustering   (fallback)
 • Feature engineering from alert payloads
 • Cluster labelling via centroid analysis
 • Incident grouping recommendations
 • Analyst feedback ingestion (online learning)

 Endpoints:
   POST /cluster           — Cluster a batch of alerts
   POST /feedback          — Ingest analyst label correction
   GET  /cluster/{job_id}  — Retrieve clustering result
   GET  /health            — Health check

 Run: uvicorn alert_clustering:app --host 0.0.0.0 --port 8002
══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

# ── Optional heavy deps — graceful degradation ───────────────────
try:
    import hdbscan
    HAS_HDBSCAN = True
except ImportError:
    HAS_HDBSCAN = False
    logging.warning("hdbscan not installed — falling back to DBSCAN")

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.feature_extraction.text import TfidfVectorizer
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logging.error("scikit-learn not installed — clustering unavailable")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("alert-clustering")

app = FastAPI(
    title="Wadjet-Eye Alert Clustering Service",
    description="HDBSCAN/DBSCAN alert clustering with analyst feedback loop",
    version="1.2.0",
)

# ── In-memory job store (replace with Redis/Supabase in production) ──
_jobs: Dict[str, Dict] = {}
_feedback_store: List[Dict] = []

# ── SEVERITY WEIGHTS ──────────────────────────────────────────────
SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "informational": 0.1,
    "unknown": 0.0,
}

# ── MITRE TACTIC ENCODING ─────────────────────────────────────────
TACTIC_INDEX = {
    "initial-access": 0, "execution": 1, "persistence": 2,
    "privilege-escalation": 3, "defense-evasion": 4, "credential-access": 5,
    "discovery": 6, "lateral-movement": 7, "collection": 8,
    "command-and-control": 9, "exfiltration": 10, "impact": 11,
    "reconnaissance": 12, "resource-development": 13,
}


# ── Pydantic models ───────────────────────────────────────────────

class AlertPayload(BaseModel):
    id: str
    title: str
    severity: str = "unknown"
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    tenant_id: Optional[str] = None
    created_at: Optional[str] = None
    ioc_count: int = 0
    tags: List[str] = []

    @validator("severity")
    def lowercase_severity(cls, v):
        return v.lower() if v else "unknown"


class ClusterRequest(BaseModel):
    alerts: List[AlertPayload] = Field(..., min_items=2, max_items=10000)
    algorithm: str = Field(default="hdbscan", regex="^(hdbscan|dbscan)$")
    min_cluster_size: int = Field(default=3, ge=2, le=100)
    min_samples: int = Field(default=2, ge=1, le=50)
    epsilon: float = Field(default=0.5, ge=0.01, le=10.0)
    time_weight: float = Field(default=0.3, ge=0.0, le=1.0)
    tenant_id: Optional[str] = None
    async_mode: bool = False


class FeedbackPayload(BaseModel):
    cluster_id: str
    alert_ids: List[str]
    analyst_label: str          # "true_positive" | "false_positive" | "duplicate"
    correct_cluster: Optional[str] = None
    analyst_id: str
    notes: Optional[str] = None


class ClusterResult(BaseModel):
    job_id: str
    status: str
    total_alerts: int
    total_clusters: int
    noise_alerts: int
    clusters: List[Dict[str, Any]]
    execution_ms: float
    algorithm: str
    created_at: str


# ── Feature engineering ───────────────────────────────────────────

def _parse_timestamp(ts_str: Optional[str]) -> float:
    """Convert ISO timestamp to Unix epoch float. Returns 0.0 on failure."""
    if not ts_str:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def _hash_categorical(value: Optional[str], buckets: int = 100) -> float:
    """Hash a categorical string into a float in [0, 1]."""
    if not value:
        return 0.0
    h = int(hashlib.md5(value.encode()).hexdigest()[:8], 16)
    return (h % buckets) / buckets


def extract_features(alerts: List[AlertPayload]) -> Tuple[np.ndarray, List[str]]:
    """
    Build a numeric feature matrix from alert payloads.

    Feature vector (14 dimensions):
      [0]  severity_score        (0.0 – 1.0)
      [1]  risk_score_norm       (0.0 – 1.0)
      [2]  confidence_norm       (0.0 – 1.0)
      [3]  tactic_enc            (0.0 – 1.0, one-hot index / 14)
      [4]  host_hash             (0.0 – 1.0)
      [5]  user_hash             (0.0 – 1.0)
      [6]  source_ip_hash        (0.0 – 1.0)
      [7]  category_hash         (0.0 – 1.0)
      [8]  time_norm             (0.0 – 1.0, relative within batch)
      [9]  ioc_count_norm        (0.0 – 1.0, log-scaled)
      [10] tag_count_norm        (0.0 – 1.0)
      [11] technique_hash        (0.0 – 1.0)
      [12] tenant_hash           (0.0 – 1.0)
      [13] title_tfidf_pc1       (first TF-IDF principal component — textual similarity)
    """
    if not HAS_SKLEARN:
        raise RuntimeError("scikit-learn not available for feature extraction")

    timestamps = [_parse_timestamp(a.created_at) for a in alerts]
    min_ts = min(t for t in timestamps if t > 0) if any(t > 0 for t in timestamps) else 0.0
    max_ts = max(timestamps) if timestamps else 0.0
    ts_range = max(max_ts - min_ts, 1.0)

    # TF-IDF on titles for textual similarity
    titles = [a.title or "" for a in alerts]
    try:
        tfidf = TfidfVectorizer(max_features=200, ngram_range=(1, 2), sublinear_tf=True)
        tfidf_matrix = tfidf.fit_transform(titles).toarray()
        # Reduce to 1 dimension via SVD if matrix is non-trivial
        if tfidf_matrix.shape[1] > 1:
            from sklearn.decomposition import TruncatedSVD
            svd = TruncatedSVD(n_components=1, random_state=42)
            title_pc1 = svd.fit_transform(tfidf_matrix).flatten()
            # Normalize to [0, 1]
            pc1_min, pc1_max = title_pc1.min(), title_pc1.max()
            if pc1_max > pc1_min:
                title_pc1 = (title_pc1 - pc1_min) / (pc1_max - pc1_min)
        else:
            title_pc1 = tfidf_matrix.flatten()
    except Exception:
        title_pc1 = np.zeros(len(alerts))

    rows = []
    for i, alert in enumerate(alerts):
        ts = timestamps[i]
        tactic_val = (TACTIC_INDEX.get(alert.mitre_tactic or "", -1) + 1) / (len(TACTIC_INDEX) + 1)
        ioc_log = np.log1p(alert.ioc_count) / np.log1p(100)
        tag_norm = min(len(alert.tags), 20) / 20.0
        time_norm = (ts - min_ts) / ts_range if ts > 0 else 0.5

        row = [
            SEVERITY_SCORES.get(alert.severity, 0.0),           # [0]
            alert.risk_score / 100.0,                            # [1]
            alert.confidence / 100.0,                            # [2]
            tactic_val,                                          # [3]
            _hash_categorical(alert.host),                       # [4]
            _hash_categorical(alert.user),                       # [5]
            _hash_categorical(alert.source_ip),                  # [6]
            _hash_categorical(alert.category),                   # [7]
            time_norm,                                           # [8]
            float(ioc_log),                                      # [9]
            float(tag_norm),                                     # [10]
            _hash_categorical(alert.mitre_technique),            # [11]
            _hash_categorical(alert.tenant_id),                  # [12]
            float(title_pc1[i]) if i < len(title_pc1) else 0.0, # [13]
        ]
        rows.append(row)

    feature_names = [
        "severity", "risk_score", "confidence", "tactic",
        "host", "user", "source_ip", "category",
        "time", "ioc_count", "tag_count", "technique",
        "tenant", "title_similarity",
    ]

    return np.array(rows, dtype=np.float32), feature_names


def run_hdbscan(X: np.ndarray, min_cluster_size: int, min_samples: int) -> np.ndarray:
    """Run HDBSCAN clustering. Returns label array (-1 = noise)."""
    if not HAS_HDBSCAN:
        logger.warning("HDBSCAN unavailable, falling back to DBSCAN")
        return run_dbscan(X, epsilon=0.5, min_samples=min_samples)

    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
        cluster_selection_method="eom",
        prediction_data=True,
        core_dist_n_jobs=-1,
    )
    return clusterer.fit_predict(X)


def run_dbscan(X: np.ndarray, epsilon: float, min_samples: int) -> np.ndarray:
    """Run DBSCAN clustering. Returns label array (-1 = noise)."""
    if not HAS_SKLEARN:
        raise RuntimeError("scikit-learn not available")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    dbscan = DBSCAN(
        eps=epsilon,
        min_samples=min_samples,
        metric="euclidean",
        n_jobs=-1,
    )
    return dbscan.fit_predict(X_scaled)


def build_cluster_summaries(
    alerts: List[AlertPayload],
    labels: np.ndarray,
    algorithm: str,
) -> List[Dict[str, Any]]:
    """Group alerts by cluster label and compute per-cluster statistics."""
    from collections import Counter

    cluster_map: Dict[int, List[int]] = {}
    for idx, label in enumerate(labels):
        cluster_map.setdefault(int(label), []).append(idx)

    clusters = []
    for label, indices in sorted(cluster_map.items()):
        if label == -1:
            # Noise points — individual unclustered alerts
            continue

        cluster_alerts = [alerts[i] for i in indices]
        severities = [a.severity for a in cluster_alerts]
        tactics = [a.mitre_tactic for a in cluster_alerts if a.mitre_tactic]
        hosts = [a.host for a in cluster_alerts if a.host]
        users = [a.user for a in cluster_alerts if a.user]

        dominant_severity = Counter(severities).most_common(1)[0][0] if severities else "unknown"
        dominant_tactic = Counter(tactics).most_common(1)[0][0] if tactics else None
        unique_hosts = list(set(hosts))
        unique_users = list(set(users))

        risk_scores = [a.risk_score for a in cluster_alerts]
        avg_risk = float(np.mean(risk_scores)) if risk_scores else 0.0
        max_risk = float(np.max(risk_scores)) if risk_scores else 0.0

        # Generate cluster label from dominant patterns
        cluster_label = _generate_cluster_label(cluster_alerts, dominant_tactic)

        clusters.append({
            "cluster_id": f"cluster-{label:04d}",
            "cluster_index": label,
            "alert_count": len(indices),
            "alert_ids": [alerts[i].id for i in indices],
            "dominant_severity": dominant_severity,
            "dominant_tactic": dominant_tactic,
            "avg_risk_score": round(avg_risk, 2),
            "max_risk_score": round(max_risk, 2),
            "unique_hosts": unique_hosts[:10],
            "unique_users": unique_users[:10],
            "cluster_label": cluster_label,
            "recommended_action": _recommend_action(dominant_severity, max_risk),
            "incident_candidate": max_risk >= 60 or len(indices) >= 5,
        })

    return sorted(clusters, key=lambda c: c["max_risk_score"], reverse=True)


def _generate_cluster_label(alerts: List[AlertPayload], tactic: Optional[str]) -> str:
    """Generate a human-readable label for a cluster."""
    from collections import Counter

    categories = Counter(a.category for a in alerts if a.category)
    top_cat = categories.most_common(1)[0][0] if categories else "Unknown Activity"

    tactic_str = tactic.replace("-", " ").title() if tactic else "Multi-Stage"
    count = len(alerts)

    return f"{tactic_str}: {top_cat} ({count} alerts)"


def _recommend_action(severity: str, max_risk: float) -> str:
    """Recommend analyst action based on cluster severity and risk."""
    if severity == "critical" or max_risk >= 90:
        return "IMMEDIATE_ESCALATE"
    elif severity == "high" or max_risk >= 70:
        return "CREATE_INCIDENT"
    elif severity == "medium" or max_risk >= 40:
        return "INVESTIGATE"
    else:
        return "MONITOR"


# ── Background clustering job ─────────────────────────────────────

def _run_clustering_job(job_id: str, request: ClusterRequest) -> None:
    """Execute clustering synchronously (called in background thread)."""
    import time
    start_ms = time.time() * 1000

    _jobs[job_id]["status"] = "running"

    try:
        if not HAS_SKLEARN:
            raise RuntimeError("scikit-learn not installed")

        alerts = request.alerts
        logger.info(f"[{job_id}] Clustering {len(alerts)} alerts with {request.algorithm}")

        # Feature extraction
        X, feature_names = extract_features(alerts)

        # Apply time weight — scale time dimension
        if request.time_weight > 0 and X.shape[0] > 1:
            X[:, 8] *= request.time_weight  # time feature index

        # Run clustering
        if request.algorithm == "hdbscan":
            labels = run_hdbscan(X, request.min_cluster_size, request.min_samples)
            algo_used = "hdbscan" if HAS_HDBSCAN else "dbscan-fallback"
        else:
            labels = run_dbscan(X, request.epsilon, request.min_samples)
            algo_used = "dbscan"

        # Build summaries
        clusters = build_cluster_summaries(alerts, labels, algo_used)
        noise_count = int(np.sum(labels == -1))
        total_clusters = len(clusters)

        elapsed_ms = (time.time() * 1000) - start_ms

        _jobs[job_id].update({
            "status": "completed",
            "total_alerts": len(alerts),
            "total_clusters": total_clusters,
            "noise_alerts": noise_count,
            "clusters": clusters,
            "labels": labels.tolist(),
            "execution_ms": round(elapsed_ms, 2),
            "algorithm": algo_used,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })

        logger.info(
            f"[{job_id}] Done — {total_clusters} clusters, "
            f"{noise_count} noise, {elapsed_ms:.0f}ms"
        )

    except Exception as exc:
        logger.exception(f"[{job_id}] Clustering failed: {exc}")
        _jobs[job_id].update({
            "status": "failed",
            "error": str(exc),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })


# ── Routes ────────────────────────────────────────────────────────

@app.post("/cluster", response_model=None, status_code=202)
async def cluster_alerts(request: ClusterRequest, background_tasks: BackgroundTasks):
    """
    Submit a batch of alerts for clustering.

    Returns immediately with a job_id when async_mode=true.
    Returns the full result synchronously when async_mode=false.
    """
    if not HAS_SKLEARN:
        raise HTTPException(status_code=503, detail="scikit-learn not installed — clustering unavailable")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": request.tenant_id,
        "total_alerts": len(request.alerts),
    }

    if request.async_mode:
        background_tasks.add_task(_run_clustering_job, job_id, request)
        return JSONResponse(
            status_code=202,
            content={"job_id": job_id, "status": "queued", "message": "Clustering job submitted"},
        )

    # Synchronous mode — block until done
    import threading
    done_event = threading.Event()

    def _run_and_signal():
        _run_clustering_job(job_id, request)
        done_event.set()

    t = threading.Thread(target=_run_and_signal, daemon=True)
    t.start()
    done_event.wait(timeout=300)  # 5-min max

    job = _jobs.get(job_id, {})
    if job.get("status") == "failed":
        raise HTTPException(status_code=500, detail=job.get("error", "Clustering failed"))

    return JSONResponse(status_code=200, content=job)


@app.get("/cluster/{job_id}")
async def get_cluster_result(job_id: str):
    """Retrieve the result of an async clustering job."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return JSONResponse(content=job)


@app.post("/feedback", status_code=200)
async def ingest_feedback(payload: FeedbackPayload):
    """
    Ingest analyst feedback on clustering results.

    Used by the self-learning engine to adjust future clustering
    thresholds and feature weights.
    """
    feedback_record = {
        "id": str(uuid.uuid4()),
        "cluster_id": payload.cluster_id,
        "alert_ids": payload.alert_ids,
        "analyst_label": payload.analyst_label,
        "correct_cluster": payload.correct_cluster,
        "analyst_id": payload.analyst_id,
        "notes": payload.notes,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    _feedback_store.append(feedback_record)

    # Trim to last 10k feedback entries
    if len(_feedback_store) > 10000:
        _feedback_store.pop(0)

    logger.info(
        f"Feedback recorded — cluster:{payload.cluster_id}, "
        f"label:{payload.analyst_label}, analyst:{payload.analyst_id}"
    )

    return {"status": "recorded", "feedback_id": feedback_record["id"]}


@app.get("/feedback/stats")
async def feedback_stats():
    """Return aggregated feedback statistics for the self-learning dashboard."""
    from collections import Counter

    label_counts = Counter(f["analyst_label"] for f in _feedback_store)
    return {
        "total_feedback": len(_feedback_store),
        "label_breakdown": dict(label_counts),
        "false_positive_rate": (
            label_counts.get("false_positive", 0) / max(len(_feedback_store), 1)
        ),
    }


@app.get("/health")
async def health():
    """Service health check."""
    return {
        "status": "ok",
        "service": "wadjet-eye-clustering",
        "version": "1.2.0",
        "algorithms": {
            "hdbscan": HAS_HDBSCAN,
            "dbscan": HAS_SKLEARN,
        },
        "active_jobs": len([j for j in _jobs.values() if j.get("status") == "running"]),
        "total_jobs": len(_jobs),
        "feedback_count": len(_feedback_store),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Entry point ───────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "alert_clustering:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8002")),
        workers=int(os.getenv("WORKERS", "2")),
        log_level=os.getenv("LOG_LEVEL", "info"),
    )
