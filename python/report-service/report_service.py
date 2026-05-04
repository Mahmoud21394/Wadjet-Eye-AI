#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════════
 Wadjet-Eye AI — Python PDF Report Service (Phase 8)
 python/report-service/report_service.py

 FastAPI service that generates:
 • SIGINT-style incident reports (ReportLab PDF)
 • AI-written executive summaries (via LLM)
 • Scheduled/event-driven report delivery
 • HTML → PDF conversion via WeasyPrint fallback

 Endpoints:
   POST /generate/incident      — Incident investigation report
   POST /generate/executive     — Executive summary report
   POST /generate/threat-intel  — CTI digest report
   POST /generate/soc-metrics   — SOC operations report
   GET  /reports/{report_id}    — Download generated PDF
   GET  /health                 — Health check
══════════════════════════════════════════════════════════════════
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import os, uuid, json, asyncio, logging, hashlib
from pathlib import Path

# ── PDF generation ────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib.colors import HexColor, black, white, grey
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.platypus.tableofcontents import TableOfContents
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    REPORTLAB = True
except ImportError:
    REPORTLAB = False

# ── WeasyPrint fallback ───────────────────────────────────────────
try:
    import weasyprint
    WEASYPRINT = True
except ImportError:
    WEASYPRINT = False

# ── HTTP client ───────────────────────────────────────────────────
try:
    import httpx
    HTTPX = True
except ImportError:
    import urllib.request, urllib.error
    HTTPX = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s — %(message)s')
logger = logging.getLogger('report-service')

app = FastAPI(
    title="Wadjet-Eye Report Service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)

# ── Output directory ──────────────────────────────────────────────
OUTPUT_DIR = Path(os.environ.get("REPORTS_DIR", "/reports"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Colour palette (SIGINT-style) ─────────────────────────────────
COLOURS = {
    "wadjet_dark":    HexColor("#0d1117"),
    "wadjet_primary": HexColor("#00e5ff"),
    "wadjet_accent":  HexColor("#ff6b2b"),
    "critical":       HexColor("#ff2d55"),
    "high":           HexColor("#ff6b2b"),
    "medium":         HexColor("#ffcc00"),
    "low":            HexColor("#34c759"),
    "header_bg":      HexColor("#161b22"),
    "row_even":       HexColor("#1c2128"),
    "row_odd":        HexColor("#161b22"),
    "text_primary":   HexColor("#e6edf3"),
    "text_secondary": HexColor("#8b949e"),
    "border":         HexColor("#30363d"),
} if REPORTLAB else {}

SEV_COLOURS = {
    "CRITICAL": "#ff2d55", "HIGH": "#ff6b2b",
    "MEDIUM": "#ffcc00", "LOW": "#34c759", "INFO": "#8b949e",
}


# ── Pydantic models ───────────────────────────────────────────────

class AlertRef(BaseModel):
    id: str
    title: str
    severity: str
    category: Optional[str] = None
    created_at: Optional[str] = None
    mitre_technique: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

class IocRef(BaseModel):
    type: str
    value: str
    confidence: Optional[int] = 80

class TimelineEntry(BaseModel):
    timestamp: str
    event: str
    source: Optional[str] = None
    technique: Optional[str] = None

class IncidentReportRequest(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: str = "HIGH"
    priority: str = "P1"
    analyst: str = "SOC Analyst"
    tenant: Optional[str] = None
    executive_summary: Optional[str] = None
    timeline: List[TimelineEntry] = []
    alerts: List[AlertRef] = []
    iocs: List[IocRef] = []
    affected_assets: List[str] = []
    mitre_techniques: List[str] = []
    root_cause: Optional[str] = None
    recommendations: List[str] = []
    attack_vector: Optional[str] = None
    data_exfil_suspected: bool = False
    lateral_movement: bool = False
    persistence_found: bool = False
    classification: str = "CONFIDENTIAL"
    generate_ai_summary: bool = True

class ExecutiveReportRequest(BaseModel):
    period_start: str
    period_end: str
    tenant: Optional[str] = None
    total_alerts: int = 0
    total_incidents: int = 0
    critical_incidents: int = 0
    mttd_minutes: Optional[float] = None
    mttr_minutes: Optional[float] = None
    sla_compliance: Optional[float] = None
    top_threats: List[Dict[str, Any]] = []
    attack_trends: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    classification: str = "CONFIDENTIAL"

class SocMetricsReportRequest(BaseModel):
    period_start: str
    period_end: str
    metrics: Dict[str, Any] = {}
    analyst_workload: List[Dict[str, Any]] = []
    sla_compliance: Optional[Dict[str, Any]] = None
    classification: str = "INTERNAL"


# ── PDF Builder ───────────────────────────────────────────────────

class WadjetPdfBuilder:
    """ReportLab-based SIGINT-style PDF generator."""

    def __init__(self):
        if not REPORTLAB:
            raise RuntimeError("ReportLab not installed. Run: pip install reportlab")
        self.styles = getSampleStyleSheet()
        self._register_styles()

    def _register_styles(self):
        self.styles.add(ParagraphStyle(
            name="WadjetTitle",
            parent=self.styles["Heading1"],
            fontSize=22, textColor=COLOURS["wadjet_primary"],
            spaceAfter=6, spaceBefore=0, alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        ))
        self.styles.add(ParagraphStyle(
            name="WadjetH2",
            parent=self.styles["Heading2"],
            fontSize=14, textColor=COLOURS["wadjet_primary"],
            spaceAfter=4, spaceBefore=12, alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        ))
        self.styles.add(ParagraphStyle(
            name="WadjetBody",
            parent=self.styles["Normal"],
            fontSize=10, textColor=COLOURS["text_primary"],
            spaceAfter=6, leading=14, alignment=TA_JUSTIFY,
        ))
        self.styles.add(ParagraphStyle(
            name="WadjetCaption",
            parent=self.styles["Normal"],
            fontSize=8, textColor=COLOURS["text_secondary"],
            spaceAfter=4, alignment=TA_LEFT,
        ))
        self.styles.add(ParagraphStyle(
            name="WadjetCode",
            parent=self.styles["Normal"],
            fontSize=8, fontName="Courier",
            textColor=COLOURS["wadjet_primary"],
            backColor=COLOURS["header_bg"],
            spaceAfter=2, leftIndent=12,
        ))
        self.styles.add(ParagraphStyle(
            name="WadjetLabel",
            parent=self.styles["Normal"],
            fontSize=9, textColor=COLOURS["text_secondary"],
            spaceAfter=2, fontName="Helvetica-Bold",
        ))

    def _severity_colour(self, severity: str):
        colour_hex = SEV_COLOURS.get(severity.upper(), "#8b949e")
        return HexColor(colour_hex)

    def _header_footer(self, canvas, doc, title: str, classification: str):
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(COLOURS["header_bg"])
        canvas.rect(0, h - 40, w, 40, fill=1, stroke=0)
        canvas.setFillColor(COLOURS["wadjet_primary"])
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(20, h - 25, "WADJET-EYE AI — THREAT INTELLIGENCE PLATFORM")
        canvas.setFillColor(COLOURS["critical"])
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawRightString(w - 20, h - 25, f"⚠ {classification}")

        # Footer bar
        canvas.setFillColor(COLOURS["header_bg"])
        canvas.rect(0, 0, w, 30, fill=1, stroke=0)
        canvas.setFillColor(COLOURS["text_secondary"])
        canvas.setFont("Helvetica", 7)
        canvas.drawString(20, 10, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawCentredString(w / 2, 10, title[:80])
        canvas.drawRightString(w - 20, 10, f"Page {doc.page}")

        canvas.restoreState()

    def build_incident_report(self, req: IncidentReportRequest, output_path: Path) -> Path:
        doc = SimpleDocTemplate(
            str(output_path), pagesize=A4,
            rightMargin=1.5*cm, leftMargin=1.5*cm,
            topMargin=2.5*cm, bottomMargin=2*cm,
            title=req.title, author="Wadjet-Eye AI",
        )

        story = []
        s = self.styles
        sev_col = self._severity_colour(req.severity)

        def on_page(canvas, doc):
            self._header_footer(canvas, doc, req.title, req.classification)

        # ── Cover section ────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(f"INCIDENT REPORT", s["WadjetTitle"]))
        story.append(Paragraph(req.title, s["WadjetH2"]))
        story.append(HRFlowable(width="100%", thickness=2, color=COLOURS["wadjet_primary"], spaceAfter=8))

        meta_data = [
            ["Incident ID", req.incident_id,     "Classification", req.classification],
            ["Severity",    req.severity,          "Priority",       req.priority],
            ["Analyst",     req.analyst,           "Report Date",    datetime.now(timezone.utc).strftime("%Y-%m-%d")],
        ]
        if req.tenant:
            meta_data.append(["Tenant", req.tenant, "", ""])

        meta_table = Table(meta_data, colWidths=[3*cm, 7*cm, 3*cm, 7*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), COLOURS["row_even"]),
            ("TEXTCOLOR",     (0, 0), (0, -1), COLOURS["text_secondary"]),
            ("TEXTCOLOR",     (2, 0), (2, -1), COLOURS["text_secondary"]),
            ("TEXTCOLOR",     (1, 0), (1, -1), COLOURS["text_primary"]),
            ("TEXTCOLOR",     (3, 0), (3, -1), COLOURS["text_primary"]),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",      (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, COLOURS["border"]),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
            ("PADDING",       (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.4*cm))

        # Severity badge row
        sev_table = Table([[f"SEVERITY: {req.severity}"]], colWidths=[4*cm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_col),
            ("TEXTCOLOR",  (0, 0), (-1, -1), white),
            ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 11),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("PADDING",    (0, 0), (-1, -1), 8),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.4*cm))

        # ── Executive Summary ────────────────────────────────────
        story.append(Paragraph("EXECUTIVE SUMMARY", s["WadjetH2"]))
        summary_text = req.executive_summary or (
            f"A {req.severity} severity security incident was detected by the Wadjet-Eye AI platform. "
            f"The incident involves {len(req.alerts)} alert(s) and affects {len(req.affected_assets)} asset(s). "
            f"{'Lateral movement was observed. ' if req.lateral_movement else ''}"
            f"{'Data exfiltration is suspected. ' if req.data_exfil_suspected else ''}"
            f"{'Persistence mechanisms were identified. ' if req.persistence_found else ''}"
            f"Immediate investigation and remediation is required."
        )
        story.append(Paragraph(summary_text, s["WadjetBody"]))
        story.append(Spacer(1, 0.3*cm))

        # ── Key Findings ─────────────────────────────────────────
        flags = []
        if req.lateral_movement:      flags.append("⚠ Lateral Movement Detected")
        if req.data_exfil_suspected:  flags.append("⚠ Data Exfiltration Suspected")
        if req.persistence_found:     flags.append("⚠ Persistence Mechanism Found")
        if flags:
            flag_data = [[f] for f in flags]
            flag_table = Table(flag_data, colWidths=[18*cm])
            flag_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), COLOURS["critical"]),
                ("TEXTCOLOR",  (0, 0), (-1, -1), white),
                ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("PADDING",    (0, 0), (-1, -1), 6),
            ]))
            story.append(flag_table)
            story.append(Spacer(1, 0.3*cm))

        # ── Attack Timeline ──────────────────────────────────────
        if req.timeline:
            story.append(Paragraph("ATTACK TIMELINE", s["WadjetH2"]))
            tl_data = [["Timestamp (UTC)", "Event", "Technique"]]
            for entry in req.timeline:
                tl_data.append([
                    entry.timestamp[:19].replace("T", " "),
                    entry.event[:80],
                    entry.technique or "",
                ])
            tl_table = Table(tl_data, colWidths=[4.5*cm, 10*cm, 3.5*cm])
            tl_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), COLOURS["header_bg"]),
                ("TEXTCOLOR",    (0, 0), (-1, 0), COLOURS["wadjet_primary"]),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("GRID",         (0, 0), (-1, -1), 0.3, COLOURS["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
                ("TEXTCOLOR",    (0, 1), (-1, -1), COLOURS["text_primary"]),
                ("PADDING",      (0, 0), (-1, -1), 5),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(tl_table)
            story.append(Spacer(1, 0.3*cm))

        # ── Alerts table ─────────────────────────────────────────
        if req.alerts:
            story.append(Paragraph("ASSOCIATED ALERTS", s["WadjetH2"]))
            alert_data = [["ID", "Title", "Severity", "Technique", "Timestamp"]]
            for a in req.alerts[:20]:
                alert_data.append([
                    a.id[:8] + "...",
                    a.title[:40],
                    a.severity,
                    a.mitre_technique or "",
                    (a.created_at or "")[:10],
                ])
            at = Table(alert_data, colWidths=[2.5*cm, 8*cm, 2.5*cm, 3*cm, 2.5*cm])
            at.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), COLOURS["header_bg"]),
                ("TEXTCOLOR",    (0, 0), (-1, 0), COLOURS["wadjet_primary"]),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("GRID",         (0, 0), (-1, -1), 0.3, COLOURS["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
                ("TEXTCOLOR",    (0, 1), (-1, -1), COLOURS["text_primary"]),
                ("PADDING",      (0, 0), (-1, -1), 4),
            ]))
            story.append(at)
            story.append(Spacer(1, 0.3*cm))

        # ── IOCs ─────────────────────────────────────────────────
        if req.iocs:
            story.append(Paragraph("INDICATORS OF COMPROMISE (IOCs)", s["WadjetH2"]))
            ioc_data = [["Type", "Value", "Confidence"]]
            for ioc in req.iocs[:30]:
                ioc_data.append([ioc.type.upper(), ioc.value[:60], f"{ioc.confidence or 80}%"])
            ioc_t = Table(ioc_data, colWidths=[3*cm, 12*cm, 3*cm])
            ioc_t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOURS["header_bg"]),
                ("TEXTCOLOR",  (0, 0), (-1, 0), COLOURS["wadjet_primary"]),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
                ("GRID",       (0, 0), (-1, -1), 0.3, COLOURS["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
                ("TEXTCOLOR",  (0, 1), (-1, -1), COLOURS["text_primary"]),
                ("FONTNAME",   (1, 1), (1, -1), "Courier"),
                ("PADDING",    (0, 0), (-1, -1), 4),
            ]))
            story.append(ioc_t)
            story.append(Spacer(1, 0.3*cm))

        # ── MITRE ATT&CK ─────────────────────────────────────────
        if req.mitre_techniques:
            story.append(Paragraph("MITRE ATT&CK TECHNIQUES", s["WadjetH2"]))
            mitre_text = ", ".join(req.mitre_techniques)
            story.append(Paragraph(mitre_text, s["WadjetCode"]))
            story.append(Spacer(1, 0.3*cm))

        # ── Root cause ────────────────────────────────────────────
        if req.root_cause:
            story.append(Paragraph("ROOT CAUSE ANALYSIS", s["WadjetH2"]))
            story.append(Paragraph(req.root_cause, s["WadjetBody"]))
            story.append(Spacer(1, 0.3*cm))

        # ── Recommendations ───────────────────────────────────────
        if req.recommendations:
            story.append(Paragraph("RECOMMENDATIONS", s["WadjetH2"]))
            for i, rec in enumerate(req.recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", s["WadjetBody"]))
            story.append(Spacer(1, 0.3*cm))

        # ── Affected assets ───────────────────────────────────────
        if req.affected_assets:
            story.append(Paragraph("AFFECTED ASSETS", s["WadjetH2"]))
            asset_data = [[a] for a in req.affected_assets[:20]]
            asset_t = Table(asset_data, colWidths=[18*cm])
            asset_t.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("FONTNAME", (0, 0), (-1, -1), "Courier"),
                ("TEXTCOLOR", (0, 0), (-1, -1), COLOURS["text_primary"]),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.3, COLOURS["border"]),
            ]))
            story.append(asset_t)

        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
        return output_path


# ── LLM executive summary generator ─────────────────────────────
async def generate_ai_summary(request_data: dict) -> str:
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("CLAUDE_API_KEY") or ""
    if not api_key:
        return _mock_summary(request_data)

    prompt = f"""You are a senior SOC analyst. Write a concise executive summary (150-200 words) for:

Incident: {request_data.get('title', 'Security Incident')}
Severity: {request_data.get('severity', 'HIGH')}
Alerts: {request_data.get('alert_count', 0)}
MITRE Techniques: {', '.join(request_data.get('mitre_techniques', [])[:5])}
Lateral Movement: {request_data.get('lateral_movement', False)}
Data Exfil Suspected: {request_data.get('data_exfil_suspected', False)}
Root Cause: {request_data.get('root_cause', 'Under investigation')}

Write in past tense. Focus on business impact, attacker objectives, and key actions taken.
Do not use bullet points. Return plain text only."""

    payload = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 300,
        "temperature": 0.3,
    }).encode()

    try:
        import urllib.request as urlreq
        req = urlreq.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )
        with urlreq.urlopen(req, timeout=30) as res:
            body = json.loads(res.read())
            return body["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.warning(f"LLM summary failed: {e}")
        return _mock_summary(request_data)


def _mock_summary(data: dict) -> str:
    return (
        f"A {data.get('severity','HIGH')} severity incident was detected by the Wadjet-Eye AI platform. "
        f"Security monitoring identified {data.get('alert_count', 0)} correlated alert(s) indicating "
        f"{'lateral movement and ' if data.get('lateral_movement') else ''}"
        f"{'possible data exfiltration. ' if data.get('data_exfil_suspected') else 'a security threat. '}"
        f"The detection engine mapped activity to {len(data.get('mitre_techniques', []))} MITRE ATT&CK technique(s). "
        f"Immediate response actions were initiated by the SOC team. "
        f"A full investigation is underway to determine the complete scope and impact of the incident."
    )


# ── API Routes ────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "reportlab": REPORTLAB,
        "weasyprint": WEASYPRINT,
        "output_dir": str(OUTPUT_DIR),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/generate/incident")
async def generate_incident_report(req: IncidentReportRequest, background_tasks: BackgroundTasks):
    report_id = str(uuid.uuid4())
    filename  = f"incident_{report_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path  = OUTPUT_DIR / filename

    if req.generate_ai_summary and not req.executive_summary:
        req.executive_summary = await generate_ai_summary({
            "title":              req.title,
            "severity":           req.severity,
            "alert_count":        len(req.alerts),
            "mitre_techniques":   req.mitre_techniques,
            "lateral_movement":   req.lateral_movement,
            "data_exfil_suspected": req.data_exfil_suspected,
            "root_cause":         req.root_cause,
        })

    if not REPORTLAB:
        raise HTTPException(status_code=503, detail="ReportLab not installed. Run: pip install reportlab")

    builder = WadjetPdfBuilder()
    try:
        builder.build_incident_report(req, out_path)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return JSONResponse({
        "report_id":    report_id,
        "filename":     filename,
        "download_url": f"/reports/{report_id}",
        "file_size":    out_path.stat().st_size,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }, status_code=201)


@app.post("/generate/executive")
async def generate_executive_report(req: ExecutiveReportRequest):
    if not REPORTLAB:
        raise HTTPException(status_code=503, detail="ReportLab not installed")

    report_id = str(uuid.uuid4())
    filename  = f"executive_{report_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path  = OUTPUT_DIR / filename

    doc = SimpleDocTemplate(str(out_path), pagesize=A4,
                            rightMargin=1.5*cm, leftMargin=1.5*cm,
                            topMargin=2.5*cm, bottomMargin=2*cm)
    builder = WadjetPdfBuilder()
    story   = []
    s       = builder.styles

    story.append(Paragraph("EXECUTIVE SECURITY BRIEF", s["WadjetTitle"]))
    story.append(Paragraph(f"Period: {req.period_start[:10]} — {req.period_end[:10]}", s["WadjetH2"]))
    story.append(HRFlowable(width="100%", thickness=2, color=COLOURS["wadjet_primary"], spaceAfter=8))

    kpi_data = [
        ["Total Alerts", str(req.total_alerts),   "Total Incidents",  str(req.total_incidents)],
        ["Critical Inc.", str(req.critical_incidents), "SLA Compliance",
         f"{req.sla_compliance:.1f}%" if req.sla_compliance is not None else "N/A"],
        ["MTTD",
         f"{req.mttd_minutes:.1f} min" if req.mttd_minutes is not None else "N/A",
         "MTTR",
         f"{req.mttr_minutes:.1f} min" if req.mttr_minutes is not None else "N/A"],
    ]
    kpi_t = Table(kpi_data, colWidths=[4*cm, 5*cm, 4*cm, 5*cm])
    kpi_t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), COLOURS["row_even"]),
        ("TEXTCOLOR",   (0, 0), (0, -1), COLOURS["text_secondary"]),
        ("TEXTCOLOR",   (2, 0), (2, -1), COLOURS["text_secondary"]),
        ("TEXTCOLOR",   (1, 0), (1, -1), COLOURS["wadjet_primary"]),
        ("TEXTCOLOR",   (3, 0), (3, -1), COLOURS["wadjet_primary"]),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 11),
        ("GRID",        (0, 0), (-1, -1), 0.5, COLOURS["border"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
        ("ALIGN",       (3, 0), (3, -1), "CENTER"),
        ("PADDING",     (0, 0), (-1, -1), 10),
    ]))
    story.append(kpi_t)
    story.append(Spacer(1, 0.4*cm))

    if req.top_threats:
        story.append(Paragraph("TOP THREATS THIS PERIOD", s["WadjetH2"]))
        th_data = [["Threat", "Count", "Severity"]]
        for t in req.top_threats[:10]:
            th_data.append([str(t.get("name", "")), str(t.get("count", "")), str(t.get("severity", ""))])
        th_t = Table(th_data, colWidths=[10*cm, 4*cm, 4*cm])
        th_t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), COLOURS["header_bg"]),
            ("TEXTCOLOR",   (0, 0), (-1, 0), COLOURS["wadjet_primary"]),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.3, COLOURS["border"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOURS["row_even"], COLOURS["row_odd"]]),
            ("TEXTCOLOR",   (0, 1), (-1, -1), COLOURS["text_primary"]),
            ("PADDING",     (0, 0), (-1, -1), 5),
        ]))
        story.append(th_t)
        story.append(Spacer(1, 0.3*cm))

    if req.recommendations:
        story.append(Paragraph("STRATEGIC RECOMMENDATIONS", s["WadjetH2"]))
        for i, rec in enumerate(req.recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", s["WadjetBody"]))

    def on_page(canvas, doc):
        builder._header_footer(canvas, doc, "Executive Security Brief", req.classification)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    return JSONResponse({
        "report_id":    report_id,
        "filename":     filename,
        "download_url": f"/reports/{report_id}",
        "file_size":    out_path.stat().st_size,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }, status_code=201)


@app.get("/reports/{report_id}")
async def download_report(report_id: str):
    matches = list(OUTPUT_DIR.glob(f"*{report_id[:8]}*.pdf"))
    if not matches:
        raise HTTPException(status_code=404, detail="Report not found")

    path = matches[0]
    return FileResponse(
        str(path),
        media_type="application/pdf",
        filename=path.name,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


@app.get("/reports")
async def list_reports():
    reports = []
    for f in sorted(OUTPUT_DIR.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]:
        reports.append({
            "filename":    f.name,
            "size":        f.stat().st_size,
            "created_at":  datetime.fromtimestamp(f.stat().st_ctime, tz=timezone.utc).isoformat(),
        })
    return {"reports": reports, "total": len(reports)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "report_service:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5002)),
        reload=False,
        workers=int(os.environ.get("WORKERS", 2)),
        log_level="info",
    )
