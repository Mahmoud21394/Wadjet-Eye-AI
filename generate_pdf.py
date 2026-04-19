"""
Wadjet-Eye AI — Enterprise Platform PDF Generator
Generates a premium, client-facing PDF document.
"""

import io
import math
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import (
    Color, HexColor, white, black
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import Flowable
from reportlab.graphics.shapes import (
    Drawing, Rect, Circle, Line, String, Polygon,
    Group, Path
)
from reportlab.graphics import renderPDF
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Color palette ────────────────────────────────────────────────────────────
C_BG          = HexColor('#050a14')      # deep black-blue page bg
C_BG2         = HexColor('#0a0f1e')      # card bg
C_BG3         = HexColor('#0f1729')      # lighter card
C_BORDER      = HexColor('#1e3a5f')      # border lines
C_BORDER2     = HexColor('#162040')
C_NEON        = HexColor('#00d4ff')      # primary neon cyan
C_NEON2       = HexColor('#00ff94')      # secondary neon green
C_NEON3       = HexColor('#7c3aed')      # purple accent
C_NEON4       = HexColor('#f59e0b')      # amber
C_NEON5       = HexColor('#ef4444')      # red
C_TEXT        = HexColor('#e2e8f0')      # primary text
C_TEXT2       = HexColor('#94a3b8')      # secondary text
C_TEXT3       = HexColor('#64748b')      # muted text
C_HEADING     = HexColor('#f1f5f9')      # bright headings
C_ACCENT_LINE = HexColor('#1e3a5f')

PAGE_W, PAGE_H = A4

# ── Helper: draw a full-bleed dark background on every page ─────────────────
def draw_page_background(canv, doc):
    canv.saveState()
    # Main background
    canv.setFillColor(C_BG)
    canv.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    # Subtle grid lines (horizontal)
    canv.setStrokeColor(HexColor('#0d1a2e'))
    canv.setLineWidth(0.3)
    for y in range(0, int(PAGE_H), 18):
        canv.line(0, y, PAGE_W, y)
    # Top accent bar
    canv.setFillColor(C_NEON)
    canv.rect(0, PAGE_H - 3, PAGE_W, 3, fill=1, stroke=0)
    # Bottom accent bar
    canv.setFillColor(C_BORDER)
    canv.rect(0, 0, PAGE_W, 2, fill=1, stroke=0)
    # Footer text
    canv.setFillColor(C_TEXT3)
    canv.setFont('Helvetica', 7)
    canv.drawString(20*mm, 6*mm, 'WADJET-EYE AI  ·  CONFIDENTIAL')
    canv.drawRightString(PAGE_W - 20*mm, 6*mm,
                         f'Page {doc.page}')
    canv.drawCentredString(PAGE_W / 2, 6*mm,
                           '© 2026 Wadjet-Eye AI. All rights reserved.')
    canv.restoreState()


def draw_cover_background(canv, doc):
    """Decorative cover page background."""
    canv.saveState()
    # Full bleed gradient simulation with layered rects
    canv.setFillColor(HexColor('#020810'))
    canv.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # Large radial glow behind the eye symbol (top-center)
    colors_glow = [
        (HexColor('#001a33'), 0.0),
        (HexColor('#00102b'), 0.4),
        (HexColor('#020810'), 1.0),
    ]
    cx, cy = PAGE_W / 2, PAGE_H * 0.62
    for i in range(40, 0, -1):
        r = i / 40
        alpha = (1 - r) * 0.6
        c = HexColor('#001433')
        canv.setFillColorRGB(0, 0.1 * (1 - r), 0.25 * (1 - r), alpha)
        radius = 200 * (i / 40)
        canv.circle(cx, cy, radius, fill=1, stroke=0)

    # Grid overlay
    canv.setStrokeColor(HexColor('#0a1a2e'))
    canv.setLineWidth(0.4)
    for y in range(0, int(PAGE_H), 20):
        canv.line(0, y, PAGE_W, y)
    for x in range(0, int(PAGE_W), 20):
        canv.line(x, 0, x, PAGE_H)

    # Diagonal accent lines
    canv.setStrokeColor(C_NEON)
    canv.setLineWidth(0.6)
    canv.setDash([2, 8])
    for i in range(-10, 30):
        x0 = i * 30
        canv.line(x0, 0, x0 + PAGE_H, PAGE_H)
    canv.setDash([])

    # Top neon bar
    canv.setFillColor(C_NEON)
    canv.rect(0, PAGE_H - 4, PAGE_W, 4, fill=1, stroke=0)

    # Bottom bar
    canv.setFillColor(C_NEON3)
    canv.rect(0, 0, PAGE_W, 4, fill=1, stroke=0)

    # Horizontal accent lines
    canv.setStrokeColor(C_BORDER)
    canv.setLineWidth(0.5)
    for y in [PAGE_H * 0.45, PAGE_H * 0.22]:
        canv.line(20*mm, y, PAGE_W - 20*mm, y)

    canv.restoreState()


# ── Reusable Flowables ────────────────────────────────────────────────────────

class NeonHRule(Flowable):
    """A two-tone horizontal rule: neon left + dim right."""
    def __init__(self, width=None, neon_frac=0.35, height=1.5, spaceAfter=8):
        super().__init__()
        self._w = width
        self._nf = neon_frac
        self._h = height
        self.spaceAfter = spaceAfter

    def wrap(self, avW, avH):
        self._w = self._w or avW
        return self._w, self._h + self.spaceAfter

    def draw(self):
        w = self._w
        # Neon segment
        self.canv.setFillColor(C_NEON)
        self.canv.rect(0, 0, w * self._nf, self._h, fill=1, stroke=0)
        # Dim segment
        self.canv.setFillColor(C_BORDER)
        self.canv.rect(w * self._nf, 0, w * (1 - self._nf), self._h,
                       fill=1, stroke=0)


class SectionHeader(Flowable):
    """Full-width section header band with neon left accent."""
    def __init__(self, title, subtitle='', section_num='', icon_char='◈',
                 accent=None, height=44):
        super().__init__()
        self.title = title
        self.subtitle = subtitle
        self.section_num = section_num
        self.icon_char = icon_char
        self.accent = accent or C_NEON
        self._height = height

    def wrap(self, avW, avH):
        self._avW = avW
        return avW, self._height + 12

    def draw(self):
        c = self.canv
        w = self._avW
        h = self._height

        # Background band
        c.setFillColor(HexColor('#0a1629'))
        c.roundRect(0, 0, w, h, 6, fill=1, stroke=0)

        # Left neon accent bar
        c.setFillColor(self.accent)
        c.roundRect(0, 0, 5, h, 3, fill=1, stroke=0)

        # Section number badge
        if self.section_num:
            c.setFillColor(self.accent)
            c.setFillColorRGB(*hex_color_to_rgb_f(self.accent), 0.15)
            c.roundRect(14, h//2 - 10, 24, 20, 4, fill=1, stroke=0)
            c.setFillColor(self.accent)
            c.setFont('Helvetica-Bold', 9)
            c.drawCentredString(26, h//2 - 3, self.section_num)

        # Icon
        x_off = 46 if self.section_num else 16
        c.setFont('Helvetica-Bold', 16)
        c.setFillColor(self.accent)
        c.drawString(x_off, h//2 - 6, self.icon_char)

        # Title
        c.setFont('Helvetica-Bold', 15)
        c.setFillColor(C_HEADING)
        c.drawString(x_off + 22, h//2 + 2, self.title)

        # Subtitle
        if self.subtitle:
            c.setFont('Helvetica', 8)
            c.setFillColor(C_TEXT2)
            c.drawString(x_off + 22, h//2 - 10, self.subtitle)

        # Right decorative dots
        for i, col in enumerate([self.accent, C_BORDER, C_BORDER]):
            c.setFillColor(col)
            c.circle(w - 16 - i*10, h//2, 3, fill=1, stroke=0)


def hex_to_rgb_f(hex_str):
    """Convert hex string like '#00d4ff' or '0x00d4ff' to (r,g,b) floats."""
    h = str(hex_str).strip().lstrip('#')
    if h.startswith('0x') or h.startswith('0X'):
        h = h[2:]
    h = h[:6]  # take only the first 6 hex chars
    return tuple(int(h[i:i+2], 16)/255 for i in (0, 2, 4))


def hex_color_to_rgb_f(color_obj):
    """Extract RGB floats from a ReportLab HexColor object."""
    return (color_obj.red, color_obj.green, color_obj.blue)

def color_hex(c):
    """Convert a ReportLab Color to a #rrggbb HTML hex string."""
    return '#{:02x}{:02x}{:02x}'.format(
        int(round(c.red * 255)),
        int(round(c.green * 255)),
        int(round(c.blue * 255)),
    )


class ModuleCard(Flowable):
    """A styled card for a module entry."""
    def __init__(self, title, icon_char, accent, tagline, features,
                 use_case, width=None, height=None):
        super().__init__()
        self.title = title
        self.icon_char = icon_char
        self.accent = accent
        self.tagline = tagline
        self.features = features
        self.use_case = use_case
        self._width = width
        self._height = height or 110

    def wrap(self, avW, avH):
        self._avW = self._width or avW
        return self._avW, self._height + 10

    def draw(self):
        c = self.canv
        w = self._avW
        h = self._height

        # Card background
        c.setFillColor(HexColor('#0a1426'))
        c.roundRect(0, 0, w, h, 8, fill=1, stroke=0)

        # Border
        c.setStrokeColor(self.accent)
        c.setLineWidth(0.8)
        c.roundRect(0, 0, w, h, 8, fill=0, stroke=1)

        # Top accent strip
        c.setFillColor(self.accent)
        c.roundRect(0, h - 4, w, 4, 3, fill=1, stroke=0)

        # Icon circle
        c.setFillColor(self.accent)
        c.setFillColorRGB(*hex_color_to_rgb_f(self.accent), 0.15)
        c.circle(30, h - 28, 18, fill=1, stroke=0)
        c.setFillColor(self.accent)
        c.setFont('Helvetica-Bold', 16)
        c.drawCentredString(30, h - 33, self.icon_char)

        # Title
        c.setFont('Helvetica-Bold', 13)
        c.setFillColor(C_HEADING)
        c.drawString(58, h - 22, self.title)

        # Tagline
        c.setFont('Helvetica-Oblique', 8)
        c.setFillColor(self.accent)
        c.drawString(58, h - 34, self.tagline)

        # Divider
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.line(12, h - 46, w - 12, h - 46)

        # Features
        y = h - 58
        c.setFont('Helvetica-Bold', 7.5)
        c.setFillColor(C_TEXT2)
        c.drawString(12, y, 'KEY FEATURES')
        y -= 12
        c.setFont('Helvetica', 8)
        for feat in self.features[:4]:
            c.setFillColor(self.accent)
            c.circle(20, y + 3, 2.5, fill=1, stroke=0)
            c.setFillColor(C_TEXT)
            c.drawString(28, y, feat)
            y -= 11

        # Use Case label
        uc_y = 14
        c.setFillColor(HexColor('#0f1e35'))
        c.roundRect(10, uc_y - 4, w - 20, 16, 3, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 7)
        c.setFillColor(self.accent)
        c.drawString(16, uc_y + 4, 'USE CASE:')
        c.setFont('Helvetica', 7.5)
        c.setFillColor(C_TEXT2)
        c.drawString(62, uc_y + 4, self.use_case[:85])


class ArchLayerDiagram(Flowable):
    """5-layer architecture stack diagram."""
    def __init__(self, width=None, height=200):
        super().__init__()
        self._w = width
        self._h = height

    def wrap(self, avW, avH):
        self._w = self._w or avW
        return self._w, self._h + 10

    def draw(self):
        c = self.canv
        w = self._w
        h = self._h

        layers = [
            ('05', 'VISUALIZATION LAYER',       'Dashboards · UI · Executive Reports',          C_NEON,  '⬛'),
            ('04', 'RESPONSE & AUTOMATION',      'SOAR · Playbooks · Orchestration',              C_NEON2, '⬛'),
            ('03', 'DETECTION & ANALYTICS',      'Rules Engine · Anomaly Detection · Alerts',     HexColor('#f97316'), '⬛'),
            ('02', 'PROCESSING & INTELLIGENCE',  'AI Engine · Correlation · Enrichment',          C_NEON3, '⬛'),
            ('01', 'DATA COLLECTION LAYER',      'Collectors · APIs · Syslog · Integrations',     HexColor('#ec4899'), '⬛'),
        ]

        lh = (h - 10) / len(layers)
        for i, (num, name, desc, col, _) in enumerate(layers):
            y = (len(layers) - 1 - i) * lh + 5
            lw = w - 40 + i * 8  # trapezoid effect: wider at bottom
            x = (w - lw) / 2

            # Shadow
            c.setFillColor(HexColor('#010508'))
            c.roundRect(x + 3, y - 3, lw, lh - 4, 5, fill=1, stroke=0)

            # Main layer body
            c.setFillColor(col)
            c.setFillColorRGB(*hex_color_to_rgb_f(col), 0.12)
            c.roundRect(x, y, lw, lh - 4, 5, fill=1, stroke=0)

            # Left accent
            c.setFillColor(col)
            c.roundRect(x, y, 6, lh - 4, 3, fill=1, stroke=0)

            # Border
            c.setStrokeColor(col)
            c.setLineWidth(0.8)
            c.roundRect(x, y, lw, lh - 4, 5, fill=0, stroke=1)

            # Layer number badge
            c.setFillColor(col)
            c.setFillColorRGB(*hex_color_to_rgb_f(col), 0.25)
            c.roundRect(x + 12, y + lh//2 - 10, 22, 18, 4, fill=1, stroke=0)
            c.setFillColor(col)
            c.setFont('Helvetica-Bold', 8)
            c.drawCentredString(x + 23, y + lh//2 - 4, num)

            # Layer name
            c.setFont('Helvetica-Bold', 9.5)
            c.setFillColor(C_HEADING)
            c.drawString(x + 42, y + lh//2 + 2, name)

            # Description
            c.setFont('Helvetica', 7.5)
            c.setFillColor(C_TEXT2)
            c.drawString(x + 42, y + lh//2 - 9, desc)

            # Right indicator dots
            for j, dcol in enumerate([col, C_BORDER, C_BORDER]):
                c.setFillColor(dcol)
                c.circle(x + lw - 14 - j*9, y + lh//2 - 2, 3.5, fill=1, stroke=0)


class KPIStrip(Flowable):
    """A row of KPI stat boxes."""
    def __init__(self, stats, width=None, height=72):
        super().__init__()
        self.stats = stats
        self._w = width
        self._h = height

    def wrap(self, avW, avH):
        self._w = self._w or avW
        return self._w, self._h + 8

    def draw(self):
        c = self.canv
        w = self._w
        h = self._h
        n = len(self.stats)
        gap = 6
        bw = (w - gap * (n - 1)) / n

        for i, (val, label, col, icon) in enumerate(self.stats):
            x = i * (bw + gap)
            # Background
            c.setFillColor(HexColor('#0a1426'))
            c.roundRect(x, 0, bw, h, 6, fill=1, stroke=0)
            # Left accent
            c.setFillColor(col)
            c.roundRect(x, 0, 4, h, 3, fill=1, stroke=0)
            # Border
            c.setStrokeColor(col)
            c.setLineWidth(0.6)
            c.setStrokeColorRGB(*hex_color_to_rgb_f(col), 0.4)
            c.roundRect(x, 0, bw, h, 6, fill=0, stroke=1)
            # Icon
            c.setFont('Helvetica-Bold', 14)
            c.setFillColor(col)
            c.drawCentredString(x + bw/2, h - 22, icon)
            # Value
            c.setFont('Helvetica-Bold', 18)
            c.setFillColor(col)
            c.drawCentredString(x + bw/2, h - 38, val)
            # Label
            c.setFont('Helvetica', 7)
            c.setFillColor(C_TEXT2)
            c.drawCentredString(x + bw/2, h - 50, label.upper())


class WorkflowDiagram(Flowable):
    """Horizontal step-by-step workflow."""
    def __init__(self, steps, width=None, height=70, accent=None):
        super().__init__()
        self.steps = steps
        self._w = width
        self._h = height
        self.accent = accent or C_NEON

    def wrap(self, avW, avH):
        self._w = self._w or avW
        return self._w, self._h + 10

    def draw(self):
        c = self.canv
        w = self._w
        h = self._h
        n = len(self.steps)
        sw = w / n

        for i, (icon, label) in enumerate(self.steps):
            cx = i * sw + sw / 2
            # Connector line (not for last)
            if i < n - 1:
                c.setStrokeColor(C_BORDER)
                c.setLineWidth(1)
                c.setDash([4, 3])
                c.line(cx + sw/2 - 4, h/2, cx + sw/2 + 6, h/2)
                c.setDash([])
                # Arrow head
                c.setFillColor(C_NEON)
                ax = cx + sw/2 + 6
                p = c.beginPath()
                p.moveTo(ax, h/2)
                p.lineTo(ax-6, h/2+4)
                p.lineTo(ax-6, h/2-4)
                p.close()
                c.drawPath(p, fill=1, stroke=0)

            # Step circle
            col = self.accent if i == 0 or i == n-1 else C_BORDER
            c.setFillColor(col)
            c.setFillColorRGB(*hex_color_to_rgb_f(self.accent),
                              0.9 if i == 0 else 0.15)
            c.circle(cx, h/2, 22, fill=1, stroke=0)
            c.setStrokeColor(self.accent)
            c.setLineWidth(1.2)
            c.circle(cx, h/2, 22, fill=0, stroke=1)

            # Icon
            c.setFont('Helvetica-Bold', 13)
            c.setFillColor(C_HEADING if i == 0 else self.accent)
            c.drawCentredString(cx, h/2 - 5, icon)

            # Label below
            c.setFont('Helvetica', 7)
            c.setFillColor(C_TEXT2)
            c.drawCentredString(cx, h/2 - 26, label)


class ThreatMatrix(Flowable):
    """A mini threat heatmap / matrix visual."""
    def __init__(self, width=None, height=100):
        super().__init__()
        self._w = width
        self._h = height

    def wrap(self, avW, avH):
        self._w = self._w or avW
        return self._w, self._h + 10

    def draw(self):
        c = self.canv
        w = self._w
        h = self._h

        # Background
        c.setFillColor(HexColor('#060c1a'))
        c.roundRect(0, 0, w, h, 6, fill=1, stroke=0)

        labels_x = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        labels_y = ['INFO', 'LOW', 'MEDIUM', 'HIGH']
        data = [
            [0.1, 0.2, 0.4, 0.8],
            [0.2, 0.3, 0.6, 0.9],
            [0.3, 0.5, 0.75, 0.95],
            [0.4, 0.6, 0.85, 1.0],
        ]

        margin = 36
        cell_w = (w - margin - 10) / 4
        cell_h = (h - margin - 10) / 4

        # Y-axis labels
        for j, lbl in enumerate(labels_y):
            y = margin + 5 + j * cell_h + cell_h / 2
            c.setFont('Helvetica', 6)
            c.setFillColor(C_TEXT3)
            c.drawRightString(margin - 4, y - 3, lbl)

        # X-axis labels
        for i, lbl in enumerate(labels_x):
            x = margin + i * cell_w + cell_w / 2
            c.setFont('Helvetica', 6)
            c.setFillColor(C_TEXT3)
            c.drawCentredString(x, 6, lbl)

        # Cells
        for j in range(4):
            for i in range(4):
                intensity = data[j][i]
                x = margin + i * cell_w + 2
                y = margin + 5 + j * cell_h + 2
                cw = cell_w - 4
                ch = cell_h - 4
                # Color interpolation: blue → red
                r = intensity
                g = max(0, 0.4 - intensity * 0.4)
                b = max(0, 1 - intensity * 1.5)
                c.setFillColorRGB(r * 0.9, g * 0.3, b * 0.4, intensity * 0.8 + 0.1)
                c.roundRect(x, y, cw, ch, 3, fill=1, stroke=0)
                if intensity > 0.7:
                    c.setFont('Helvetica-Bold', 7)
                    c.setFillColor(white)
                    c.drawCentredString(x + cw/2, y + ch/2 - 3,
                                        f'{int(intensity*100)}%')

        # Title
        c.setFont('Helvetica-Bold', 8)
        c.setFillColor(C_TEXT2)
        c.drawCentredString(w/2, h - 8, 'THREAT SEVERITY MATRIX')


class DataFlowDiagram(Flowable):
    """A layered data-flow pipeline visualization."""
    def __init__(self, width=None, height=80):
        super().__init__()
        self._w = width
        self._h = height

    def wrap(self, avW, avH):
        self._w = self._w or avW
        return self._w, self._h + 10

    def draw(self):
        c = self.canv
        w = self._w
        h = self._h

        nodes = [
            ('SIEM', C_NEON,  w*0.08),
            ('EDR',  C_NEON2, w*0.08),
            ('APIs', C_NEON4, w*0.08),
            ('OSINT',HexColor('#ec4899'), w*0.08),
        ]
        pipeline = [
            ('INGEST',    C_NEON,  w*0.30),
            ('NORMALIZE', C_NEON3, w*0.44),
            ('CORRELATE', HexColor('#f97316'), w*0.58),
            ('DETECT',    C_NEON5, w*0.72),
            ('RESPOND',   C_NEON2, w*0.88),
        ]

        mid_y = h / 2

        # Source nodes
        for i, (lbl, col, _) in enumerate(nodes):
            ny = (h / (len(nodes)+1)) * (i+1)
            # Node box
            c.setFillColor(col)
            c.setFillColorRGB(*hex_color_to_rgb_f(col), 0.15)
            c.roundRect(2, ny - 10, 36, 18, 4, fill=1, stroke=0)
            c.setStrokeColor(col)
            c.setLineWidth(0.7)
            c.roundRect(2, ny - 10, 36, 18, 4, fill=0, stroke=1)
            c.setFont('Helvetica-Bold', 6.5)
            c.setFillColor(col)
            c.drawCentredString(20, ny - 3, lbl)
            # Connector to pipeline
            c.setStrokeColor(HexColor('#1e3a5f'))
            c.setLineWidth(0.6)
            c.line(38, ny, w*0.27, mid_y)

        # Pipeline stages
        for j, (lbl, col, px) in enumerate(pipeline):
            c.setFillColor(col)
            c.setFillColorRGB(*hex_color_to_rgb_f(col), 0.18)
            c.roundRect(px - 22, mid_y - 16, 44, 30, 5, fill=1, stroke=0)
            c.setStrokeColor(col)
            c.setLineWidth(1.0)
            c.roundRect(px - 22, mid_y - 16, 44, 30, 5, fill=0, stroke=1)
            c.setFont('Helvetica-Bold', 7)
            c.setFillColor(C_HEADING)
            c.drawCentredString(px, mid_y - 2, lbl)
            # Arrow between pipeline stages
            if j < len(pipeline) - 1:
                nx = pipeline[j+1][2]
                c.setStrokeColor(C_NEON)
                c.setLineWidth(1)
                c.line(px + 22, mid_y, nx - 22, mid_y)
                # arrowhead
                ax = nx - 22
                c.setFillColor(C_NEON)
                p = c.beginPath()
                p.moveTo(ax, mid_y)
                p.lineTo(ax-5, mid_y+3)
                p.lineTo(ax-5, mid_y-3)
                p.close()
                c.drawPath(p, fill=1, stroke=0)


# ── Style definitions ─────────────────────────────────────────────────────────
def build_styles():
    styles = getSampleStyleSheet()

    base = dict(
        fontName='Helvetica',
        textColor=C_TEXT,
        backColor=None,
    )

    custom = {
        'CoverTitle': ParagraphStyle('CoverTitle',
            fontName='Helvetica-Bold', fontSize=36, leading=44,
            textColor=C_HEADING, alignment=TA_CENTER, spaceAfter=6),
        'CoverTagline': ParagraphStyle('CoverTagline',
            fontName='Helvetica-Oblique', fontSize=14, leading=20,
            textColor=C_NEON, alignment=TA_CENTER, spaceAfter=16),
        'CoverMeta': ParagraphStyle('CoverMeta',
            fontName='Helvetica', fontSize=9, leading=14,
            textColor=C_TEXT2, alignment=TA_CENTER),
        'H1': ParagraphStyle('H1', fontName='Helvetica-Bold',
            fontSize=18, leading=24, textColor=C_HEADING,
            spaceBefore=14, spaceAfter=6),
        'H2': ParagraphStyle('H2', fontName='Helvetica-Bold',
            fontSize=13, leading=18, textColor=C_NEON,
            spaceBefore=10, spaceAfter=4),
        'H3': ParagraphStyle('H3', fontName='Helvetica-Bold',
            fontSize=10.5, leading=15, textColor=C_NEON2,
            spaceBefore=8, spaceAfter=3),
        'Body': ParagraphStyle('Body', fontName='Helvetica',
            fontSize=9, leading=14, textColor=C_TEXT,
            spaceBefore=2, spaceAfter=4, alignment=TA_JUSTIFY),
        'BodySm': ParagraphStyle('BodySm', fontName='Helvetica',
            fontSize=8, leading=12, textColor=C_TEXT2,
            spaceBefore=1, spaceAfter=3),
        'Bullet': ParagraphStyle('Bullet', fontName='Helvetica',
            fontSize=8.5, leading=13, textColor=C_TEXT,
            leftIndent=16, bulletIndent=4, spaceBefore=1, spaceAfter=2),
        'Caption': ParagraphStyle('Caption', fontName='Helvetica-Oblique',
            fontSize=7.5, leading=11, textColor=C_TEXT3,
            alignment=TA_CENTER, spaceAfter=6),
        'Tag': ParagraphStyle('Tag', fontName='Helvetica-Bold',
            fontSize=7, leading=10, textColor=C_NEON,
            spaceBefore=0, spaceAfter=2),
        'TableHeader': ParagraphStyle('TableHeader', fontName='Helvetica-Bold',
            fontSize=8, leading=11, textColor=C_HEADING, alignment=TA_CENTER),
        'TableCell': ParagraphStyle('TableCell', fontName='Helvetica',
            fontSize=8, leading=12, textColor=C_TEXT),
        'Mono': ParagraphStyle('Mono', fontName='Courier',
            fontSize=7.5, leading=11, textColor=C_NEON2,
            backColor=HexColor('#060c18'), leftIndent=8, rightIndent=8,
            spaceBefore=3, spaceAfter=3),
        'Callout': ParagraphStyle('Callout', fontName='Helvetica-BoldOblique',
            fontSize=10, leading=15, textColor=C_NEON4, alignment=TA_CENTER,
            spaceBefore=6, spaceAfter=6),
        'ContentsItem': ParagraphStyle('ContentsItem', fontName='Helvetica',
            fontSize=9.5, leading=16, textColor=C_TEXT, leftIndent=20),
        'ContentsNum': ParagraphStyle('ContentsNum', fontName='Helvetica-Bold',
            fontSize=9.5, leading=16, textColor=C_NEON, leftIndent=0),
    }
    return custom


# ── Content builder helpers ───────────────────────────────────────────────────

def bullet(text, style, prefix='▸'):
    return Paragraph(f'<font color="#00d4ff">{prefix}</font>  {text}', style)


def feature_table(headers, rows, styles_map, col_widths=None):
    """Build a dark-themed table."""
    header_cells = [Paragraph(h, styles_map['TableHeader']) for h in headers]
    data = [header_cells]
    for row in rows:
        data.append([Paragraph(str(c), styles_map['TableCell']) for c in row])

    col_widths = col_widths or [160*mm / len(headers)] * len(headers)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    ts = TableStyle([
        ('BACKGROUND',  (0,0), (-1,0), HexColor('#0a1f3d')),
        ('TEXTCOLOR',   (0,0), (-1,0), C_NEON),
        ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,0), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
             [HexColor('#070d1a'), HexColor('#0a1020')]),
        ('TEXTCOLOR',   (0,1), (-1,-1), C_TEXT),
        ('FONTNAME',    (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',    (0,1), (-1,-1), 8),
        ('GRID',        (0,0), (-1,-1), 0.4, C_BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING',(0,0), (-1,-1), 8),
        ('TOPPADDING',  (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        # Left accent column
        ('BACKGROUND',  (0,1), (0,-1), HexColor('#0c1626')),
        ('TEXTCOLOR',   (0,1), (0,-1), C_NEON),
        ('FONTNAME',    (0,1), (0,-1), 'Helvetica-Bold'),
    ])
    t.setStyle(ts)
    return t


def info_box(text, accent=None, style=None):
    """A highlighted callout box."""
    accent = accent or C_NEON4
    return Table(
        [[Paragraph(text, style)]],
        colWidths=['100%'],
        style=TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), HexColor('#0e1c30')),
            ('LEFTPADDING', (0,0), (-1,-1), 14),
            ('RIGHTPADDING',(0,0), (-1,-1), 14),
            ('TOPPADDING',  (0,0), (-1,-1), 10),
            ('BOTTOMPADDING',(0,0), (-1,-1), 10),
            ('BOX', (0,0), (-1,-1), 1, accent),
            ('LINEAFTER', (0,0), (-1,-1), 0, accent),
        ])
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN DOCUMENT BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def build_pdf(out_path='Wadjet-Eye-AI-Platform-Overview.pdf'):
    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=18*mm,
        rightMargin=18*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
        title='Wadjet-Eye AI — Enterprise SOC Platform',
        author='Wadjet-Eye AI',
        subject='Platform Overview & Architecture',
    )

    S = build_styles()
    story = []
    FULL_W = PAGE_W - 36*mm   # usable width

    # ─────────────────────────────────────────────────────────────────────────
    #  COVER PAGE
    # ─────────────────────────────────────────────────────────────────────────
    # We use a first-page-only template via onFirstPage
    # Build a fake cover using flowables + a custom first-page canvas cb

    # We'll use two separate doc builds: first the cover canvas, then body.
    # For simplicity use a single doc with a custom first-page callback.

    story.append(Spacer(1, 60*mm))

    # Glowing eye SVG-style text mark
    story.append(Paragraph(
        '<font color="#00d4ff" size="32">◉</font>',
        ParagraphStyle('EyeMark', fontName='Helvetica-Bold',
                       fontSize=32, leading=40,
                       textColor=C_NEON, alignment=TA_CENTER)
    ))
    story.append(Spacer(1, 8*mm))

    story.append(Paragraph('WADJET-EYE AI', S['CoverTitle']))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph(
        'AI-Powered SOC &amp; Threat Intelligence Platform',
        S['CoverTagline']
    ))
    story.append(Spacer(1, 6*mm))

    # Tag badges row
    tags = Table(
        [[
            Paragraph('<font color="#00d4ff">◈ ENTERPRISE GRADE</font>', S['Tag']),
            Paragraph('<font color="#00ff94">◈ AI-NATIVE</font>', S['Tag']),
            Paragraph('<font color="#7c3aed">◈ REAL-TIME SOC</font>', S['Tag']),
            Paragraph('<font color="#f59e0b">◈ MULTI-TENANT</font>', S['Tag']),
        ]],
        colWidths=[FULL_W/4]*4,
        style=TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('BACKGROUND', (0,0), (0,0), HexColor('#001833')),
            ('BACKGROUND', (1,0), (1,0), HexColor('#001a0d')),
            ('BACKGROUND', (2,0), (2,0), HexColor('#1a0a30')),
            ('BACKGROUND', (3,0), (3,0), HexColor('#1a0e00')),
            ('BOX', (0,0), (0,0), 0.8, C_NEON),
            ('BOX', (1,0), (1,0), 0.8, C_NEON2),
            ('BOX', (2,0), (2,0), 0.8, C_NEON3),
            ('BOX', (3,0), (3,0), 0.8, C_NEON4),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ])
    )
    story.append(tags)
    story.append(Spacer(1, 12*mm))

    # Divider line
    story.append(NeonHRule(neon_frac=0.5))
    story.append(Spacer(1, 8*mm))

    # Version & classification row
    meta_table = Table(
        [[
            Paragraph('VERSION 17.0', S['CoverMeta']),
            Paragraph('PLATFORM OVERVIEW', S['CoverMeta']),
            Paragraph('2026 — CONFIDENTIAL', S['CoverMeta']),
        ]],
        colWidths=[FULL_W/3]*3,
        style=TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER')])
    )
    story.append(meta_table)
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        'wadjet-eye-ai.vercel.app  ·  wadjet-eye-ai.onrender.com',
        S['CoverMeta']
    ))
    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  TABLE OF CONTENTS
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('TABLE OF CONTENTS', 'Document Navigation',
                               icon_char='≡', accent=C_NEON3))
    story.append(Spacer(1, 6*mm))

    toc_items = [
        ('01', 'Executive Summary', 'Platform overview, value proposition, target users'),
        ('02', 'Platform Architecture', 'High-level design, core capabilities, technology stack'),
        ('03', 'Architecture Layers', 'Five-layer model from data collection to visualization'),
        ('04', 'Module Breakdown', 'RAKAY AI, CVE Engine, Live Detections, Threat Intel, NTA, Dark Web'),
        ('05', 'Use Cases & Scenarios', 'Real SOC scenarios, incident response, threat hunting'),
        ('06', 'Key Differentiators', 'AI-driven analysis, real-time detection, SOAR, scalability'),
        ('07', 'Integration Ecosystem', 'APIs, SIEM, EDR, feeds, and enterprise connectors'),
        ('08', 'Security & Compliance', 'Multi-tenancy, RBAC, audit logging, data protection'),
        ('09', 'Conclusion & Roadmap', 'Strategic value, future vision, next steps'),
    ]

    for num, title, desc in toc_items:
        row = Table(
            [[
                Paragraph(f'<font color="#00d4ff"><b>{num}</b></font>', S['ContentsNum']),
                Paragraph(f'<b>{title}</b><br/><font size="8" color="#64748b">{desc}</font>',
                          S['ContentsItem']),
                Paragraph('· · · · · · · · · · · ·',
                          ParagraphStyle('dots', fontName='Helvetica',
                                         fontSize=8, textColor=C_BORDER,
                                         alignment=TA_RIGHT)),
            ]],
            colWidths=[18*mm, FULL_W - 40*mm, 22*mm],
            style=TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LINEBELOW', (0,0), (-1,-1), 0.3, C_BORDER2),
            ])
        )
        story.append(row)

    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  01  EXECUTIVE SUMMARY
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('EXECUTIVE SUMMARY',
                               'Platform Overview & Strategic Value',
                               section_num='01', icon_char='◈', accent=C_NEON))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph(
        'Wadjet-Eye AI is a next-generation, AI-native Security Operations Center (SOC) platform '
        'engineered to address the most demanding threat detection, investigation, and response '
        'requirements of modern enterprises. Built on a five-layer architecture spanning data '
        'ingestion through automated response, the platform unifies over 25 live CTI feeds, '
        'an AI-powered analyst (RAKAY), a CVE intelligence engine, SOAR orchestration, and '
        'real-time detection dashboards into a single, cohesive operational environment.',
        S['Body']
    ))
    story.append(Spacer(1, 3*mm))

    # KPI strip
    story.append(KPIStrip([
        ('25+',  'Live CTI Feeds',     C_NEON,  '◉'),
        ('56K+', 'IOC Database',       C_NEON2, '◈'),
        ('99.9%','Detection Uptime',   HexColor('#f97316'), '▲'),
        ('<2s',  'Alert Latency',      C_NEON3, '⚡'),
        ('100%', 'API Coverage',       C_NEON4, '⬛'),
    ], height=80))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph('Value Proposition', S['H2']))
    story.append(NeonHRule(neon_frac=0.2))

    vp_rows = [
        ['◈ Unified Visibility',
         'Single pane of glass across SIEM, EDR, network, cloud, '
         'and dark web sources — eliminating tool sprawl and alert fatigue.'],
        ['◈ AI-Driven Analysis',
         'RAKAY AI Analyst provides natural-language threat investigation, '
         'Sigma/KQL rule generation, CVE research, and MITRE ATT&CK mapping '
         'without requiring specialist expertise for every query.'],
        ['◈ Real-Time Response',
         'Sub-2-second alert latency through WebSocket-powered live feeds, '
         'combined with automated SOAR playbooks that contain threats before '
         'they escalate — reducing Mean Time to Respond (MTTR) by up to 80%.'],
        ['◈ Enterprise Scale',
         'Multi-tenant architecture supports MSSPs, large enterprises, and '
         'distributed SOC teams with granular RBAC, full audit logging, and '
         'data isolation per tenant.'],
    ]
    for vp_title, vp_desc in vp_rows:
        t = Table(
            [[
                Paragraph(f'<font color="#00d4ff"><b>{vp_title}</b></font>',
                          S['Body']),
                Paragraph(vp_desc, S['Body']),
            ]],
            colWidths=[52*mm, FULL_W - 54*mm],
            style=TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LINEBELOW', (0,0), (-1,-1), 0.3, C_BORDER2),
                ('BACKGROUND', (0,0), (0,-1), HexColor('#080f1c')),
                ('LEFTPADDING', (0,0), (0,-1), 10),
            ])
        )
        story.append(t)

    story.append(Spacer(1, 4*mm))
    story.append(Paragraph('Target Users', S['H2']))
    story.append(NeonHRule(neon_frac=0.2))

    user_data = [
        ['User Profile', 'Primary Use', 'Key Modules'],
        ['SOC Analysts (L1–L3)', 'Alert triage, live detections, investigation',
         'Live Detections · RAKAY · Case Management'],
        ['Threat Intelligence Analysts', 'IOC enrichment, threat actor profiling, dark web',
         'IOC Database · Dark Web · Threat Actors · Kill Chain'],
        ['Security Engineers', 'Detection engineering, Sigma rules, SIEM tuning',
         'Detection Engineering · CVE Engine · EDR/SIEM'],
        ['SOC Managers / CISOs', 'Executive dashboards, KPIs, SLA reporting',
         'Executive Dashboard · Reports · SOAR'],
        ['MSSP Operators', 'Multi-tenant management, customer isolation, billing',
         'Customers · RBAC Admin · Pricing · Branding'],
    ]
    story.append(feature_table(
        user_data[0], user_data[1:], S,
        col_widths=[50*mm, 65*mm, FULL_W - 117*mm]
    ))
    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  02  PLATFORM ARCHITECTURE
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('PLATFORM ARCHITECTURE',
                               'High-Level Design & Core Capabilities',
                               section_num='02', icon_char='⬛', accent=C_NEON2))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph(
        'Wadjet-Eye AI is architected as a cloud-native, microservices-oriented platform '
        'deployed across a decoupled frontend (Vercel) and backend (Render/Node.js) with '
        'Supabase as the primary persistence and real-time subscription layer. The system '
        'exposes a RESTful API with WebSocket channels for live event streaming, and integrates '
        'directly with leading OSINT sources, NVD, MITRE ATT&CK, and commercial threat feeds.',
        S['Body']
    ))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph('Data Flow Pipeline', S['H2']))
    story.append(NeonHRule(neon_frac=0.22))
    story.append(Spacer(1, 2*mm))
    story.append(DataFlowDiagram(height=90))
    story.append(Paragraph(
        'Data flows from diverse collection sources through normalization, AI-powered '
        'correlation, detection rule evaluation, and automated response stages.',
        S['Caption']
    ))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph('Technology Stack', S['H2']))
    story.append(NeonHRule(neon_frac=0.22))
    story.append(Spacer(1, 2*mm))

    stack_data = [
        ['Layer', 'Technology', 'Role'],
        ['Frontend', 'Vanilla JS · HTML5 · CSS3 · Vercel CDN',
         'SPA delivery, zero-framework, sub-100ms load'],
        ['API Gateway', 'Node.js 20 · Express.js · Render.com',
         'REST API, JWT auth, rate limiting, CORS'],
        ['WebSockets', 'Socket.IO · Native WSS (/ws/detections)',
         'Real-time bi-directional detection streaming'],
        ['Database', 'Supabase (PostgreSQL) · Row-Level Security',
         'Multi-tenant data isolation, sub-ms queries'],
        ['AI Engine', 'OpenAI GPT-4o / Anthropic Claude 3',
         'RAKAY analyst, rule generation, enrichment'],
        ['Threat Intel', 'NVD API 2.0 · 25+ CTI feeds · MITRE ATT&CK',
         'Live vulnerability & threat data'],
        ['Auth', 'Supabase Auth · JWT · Demo tokens · RBAC',
         'Three-tier authentication model'],
    ]
    story.append(feature_table(
        stack_data[0], stack_data[1:], S,
        col_widths=[35*mm, 70*mm, FULL_W - 107*mm]
    ))
    story.append(Spacer(1, 4*mm))

    story.append(info_box(
        '⚡  The platform backend on Render.com is always-on with auto-scaling. '
        'Frontend is globally distributed via Vercel\'s Edge Network with '
        'zero cold-start latency for end users.',
        accent=C_NEON4,
        style=S['BodySm']
    ))
    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  03  ARCHITECTURE LAYERS
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('ARCHITECTURE LAYERS',
                               'Five-Layer Security Operations Model',
                               section_num='03', icon_char='▲',
                               accent=HexColor('#f97316')))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph(
        'The platform is structured around five sequential operational layers, each with '
        'dedicated components, data contracts, and SOC value delivery. This layered model '
        'ensures modular extensibility while maintaining strict data flow integrity.',
        S['Body']
    ))
    story.append(Spacer(1, 3*mm))
    story.append(ArchLayerDiagram(height=185))
    story.append(Paragraph('Five-layer architecture from raw telemetry to analyst action.',
                            S['Caption']))
    story.append(Spacer(1, 4*mm))

    layers_detail = [
        {
            'num': '01', 'name': 'Data Collection Layer',
            'accent': HexColor('#ec4899'),
            'desc': (
                'The foundation of the platform. Continuously ingests security telemetry '
                'from heterogeneous sources including SIEM event streams, EDR agents, '
                'network sensors, syslog forwarders, REST API connectors, and OSINT feeds. '
                'All data is normalized to a unified event schema before handoff.'
            ),
            'components': [
                'Collector agents (Sysmon, Windows Event Log, Linux auditd)',
                'REST API integrations (VirusTotal, Shodan, AbuseIPDB, AlienVault OTX)',
                '25+ automated CTI feed parsers (STIX/TAXII, MISP, OpenCTI)',
                'IOC ingestion pipeline with deduplication and TTL management',
                'Syslog listener (UDP/TCP 514) with CEF/LEEF normalization',
            ],
            'soc_value': 'Eliminates data silos by centralizing all security telemetry into one queryable layer, reducing analyst context-switching by 70%.',
        },
        {
            'num': '02', 'name': 'Processing & Intelligence Layer',
            'accent': C_NEON3,
            'desc': (
                'The AI-powered brain of the platform. Raw events are enriched with '
                'contextual threat intelligence, correlated across time windows, and '
                'scored using ML-based risk models. RAKAY AI provides natural-language '
                'analysis at this layer.'
            ),
            'components': [
                'RAKAY AI Engine (GPT-4o / Claude 3 LLM backend)',
                'IOC enrichment: geo-location, ASN, WHOIS, passive DNS, VirusTotal',
                'Multi-source event correlation engine (time-window, entity-based)',
                'CVE intelligence: NVD API 2.0 with real-time severity tracking',
                'MITRE ATT&CK technique mapping and kill-chain positioning',
                'Threat actor attribution and campaign clustering',
            ],
            'soc_value': 'Reduces analyst investigation time from hours to minutes by delivering pre-enriched, context-rich alerts with AI-generated summaries.',
        },
        {
            'num': '03', 'name': 'Detection & Analytics Layer',
            'accent': HexColor('#f97316'),
            'desc': (
                'Applies a multi-engine detection pipeline including Sigma rule evaluation, '
                'behavioral analytics, anomaly detection, and KQL-based hunt queries. '
                'Detections are severity-scored and routed to the appropriate response workflow.'
            ),
            'components': [
                'Sigma rule engine with 500+ built-in detection rules',
                'KQL / SPL / Lucene query translation via RAKAY',
                'Behavioral baseline modeling with anomaly scoring',
                'Live detection feed (WebSocket, sub-2s latency)',
                'IOC matching against 56,000+ known indicators',
                'Geo-threat intelligence with real-time map visualization',
            ],
            'soc_value': 'Achieves industry-leading detection coverage with false-positive rates below 3% through layered detection logic and ML-based tuning.',
        },
        {
            'num': '04', 'name': 'Response & Automation Layer',
            'accent': C_NEON2,
            'desc': (
                'Closes the loop from detection to containment. Automated SOAR playbooks '
                'execute response actions — IP blocking, user suspension, host isolation, '
                'ticket creation — within seconds of detection, while case management '
                'tracks investigation workflow for human analysts.'
            ),
            'components': [
                'SOAR engine with 50+ pre-built automated playbooks',
                'Case management with SLA tracking, assignment, and audit trail',
                'Adversary simulation (what-if analysis for attack path modeling)',
                'Threat hunting workbench with saved queries and pivot analysis',
                'Executive reporting with scheduled PDF/CSV export',
                'Webhook integrations (Slack, PagerDuty, JIRA, ServiceNow)',
            ],
            'soc_value': 'Reduces Mean Time to Respond (MTTR) by up to 80% through automated first-response playbooks, freeing analysts for high-value investigations.',
        },
        {
            'num': '05', 'name': 'Visualization Layer',
            'accent': C_NEON,
            'desc': (
                'Delivers role-appropriate dashboards for every stakeholder — from the '
                'real-time SOC analyst view to the executive KPI dashboard. All views are '
                'built on live WebSocket data with zero page-refresh latency.'
            ),
            'components': [
                'Command Center: real-time KPI tiles, alert feed, case counters',
                'Executive Dashboard: trend charts, threat pressure index, SLA metrics',
                'Live Detections SOC: severity-coded feed, event-rate badge, MITRE overlay',
                'Geo-Threat Map: real-time attack origin/destination visualization',
                'Kill Chain Visualizer: MITRE ATT&CK matrix with active technique highlighting',
                'Custom branding: white-label support for MSSP deployments',
            ],
            'soc_value': 'Enables instant situational awareness across all organizational levels — from L1 analyst triage to CISO board reporting — within the same platform.',
        },
    ]

    for i, layer in enumerate(layers_detail):
        if i > 0 and i % 2 == 0:
            story.append(PageBreak())
        story.append(KeepTogether([
            Paragraph(
                f'<font color="{color_hex(layer["accent"])}">{'━'*3}</font>  '
                f'<b>Layer {layer["num"]}: {layer["name"]}</b>',
                S['H2']
            ),
            NeonHRule(neon_frac=0.18),
            Paragraph(layer['desc'], S['Body']),
            Spacer(1, 2*mm),
        ]))

        # Two-col layout: features left, soc value right
        feat_paras = [bullet(f, S['Bullet']) for f in layer['components']]
        soc_box = Table(
            [[Paragraph('<b>◈ SOC VALUE</b>', S['Tag']),],
             [Paragraph(layer['soc_value'], S['BodySm'])]],
            colWidths=['100%'],
            style=TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), HexColor('#0a1626')),
                ('BOX', (0,0), (-1,-1), 0.8, layer['accent']),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ])
        )

        two_col = Table(
            [[Table([[p] for p in feat_paras],
                    colWidths=['100%'],
                    style=TableStyle([
                        ('TOPPADDING', (0,0), (-1,-1), 1),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 1),
                    ])),
              soc_box]],
            colWidths=[FULL_W * 0.58, FULL_W * 0.38],
            style=TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ])
        )
        story.append(two_col)
        story.append(Spacer(1, 4*mm))

    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  04  MODULE BREAKDOWN
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('MODULE BREAKDOWN',
                               'Deep-Dive into Platform Capabilities',
                               section_num='04', icon_char='⬛',
                               accent=C_NEON3))
    story.append(Spacer(1, 3*mm))

    modules = [
        {
            'title': 'RAKAY — AI Security Analyst',
            'icon': '◉', 'accent': C_NEON,
            'tagline': 'Natural-language SOC analyst powered by GPT-4o / Claude 3',
            'purpose': (
                'RAKAY is the AI-native analyst embedded within the SOC platform. '
                'It accepts natural-language queries and translates them into actionable '
                'intelligence: generating Sigma detection rules, translating queries to '
                'KQL/SPL/Lucene, enriching IOCs, profiling threat actors, and researching '
                'CVEs — all within a persistent multi-session chat interface.'
            ),
            'features': [
                'Multi-LLM backend: GPT-4o (primary) with Anthropic Claude 3 fallback',
                'Tool-calling loop: sigma, kql, ioc, mitre, cve, actor, nav (max 5 iterations)',
                'Persistent session history with Supabase storage (7-day TTL)',
                'Three-tier auth: Supabase JWT · RAKAY service key · 24h demo token',
                'Session deduplication: 10s window prevents duplicate submissions',
                'Per-session mutex: one LLM call at a time, auto-release after 5 min',
                'Token usage tracking and cost logging per session',
                'Streaming response support for long-form analysis',
            ],
            'workflow': [
                ('📝', 'Analyst Query'),
                ('🔍', 'Tool Dispatch'),
                ('🤖', 'LLM Processing'),
                ('✅', 'Response'),
            ],
            'use_case': (
                'An L2 analyst asks: "Generate a Sigma rule to detect lateral movement '
                'via PsExec on Windows endpoints." RAKAY calls the sigma tool, retrieves '
                'relevant MITRE ATT&CK techniques (T1021, T1570), generates a production-ready '
                'Sigma rule with Sysmon EventID filters, and presents it with a deployment guide '
                'in under 8 seconds.'
            ),
            'table': {
                'headers': ['Capability', 'Detail'],
                'rows': [
                    ['Sigma Rule Generation', 'Full YAML output with logsource, detection, and falsepositives'],
                    ['KQL/SPL Translation', 'Convert human queries to Splunk SPL, Microsoft KQL, Elastic Lucene'],
                    ['IOC Enrichment', 'VT score, geo-location, WHOIS, passive DNS, abuse reports'],
                    ['CVE Research', 'NVD data, CVSS scoring, patch status, exploit availability'],
                    ['Threat Actor Profiling', 'TTPs, campaigns, geographic attribution, MITRE mapping'],
                    ['MITRE ATT&CK Lookup', 'Technique detail, sub-techniques, mitigations, data sources'],
                ],
                'widths': [60*mm, FULL_W - 62*mm],
            },
        },
        {
            'title': 'CVE Intelligence Engine',
            'icon': '◈', 'accent': HexColor('#ef4444'),
            'tagline': 'Real-time vulnerability tracking from NIST NVD API 2.0',
            'purpose': (
                'The CVE Intelligence Engine provides live vulnerability tracking, severity '
                'analysis, and patch status monitoring. It queries the NIST NVD API 2.0 directly '
                'via a same-origin proxy, with full rate-limit management, auto-refresh, and '
                'an interactive detail panel that always renders — even for unpatched CVEs '
                'without official remediation.'
            ),
            'features': [
                'Live NVD API 2.0 integration with 4-request staggered KPI loading',
                'CVSS v2/v3.0/v3.1 scoring with severity color-coding',
                'Patch status detection: Patched / Unpatched / Under Review',
                '"No official patch" warning banner for unpatched CVEs',
                'Exploit reference detection and CISA KEV flagging',
                'CWE weakness classification with affected systems/CPE',
                'Auto-refresh every 5 minutes with new-CVE notification',
                'Keyword search, severity filter, exploit-only filter',
            ],
            'workflow': [
                ('🔎', 'Filter/Search'),
                ('📡', 'NVD Proxy Fetch'),
                ('📊', 'Normalize'),
                ('📋', 'Detail Panel'),
            ],
            'use_case': (
                'A vulnerability manager searches for CRITICAL CVEs in the last 7 days with '
                'public exploits. The engine returns 23 results in 4.2 seconds (within NVD '
                'rate limits). Clicking CVE-2025-12345 opens a full detail panel showing '
                'no patch is available, CVSS 9.8, affected Apache HTTP Server versions, '
                'exploit references, and recommended mitigations.'
            ),
            'table': {
                'headers': ['Field', 'Source', 'Notes'],
                'rows': [
                    ['CVE ID / Title', 'NVD cve.id', 'Auto-uppercased, format-validated'],
                    ['CVSS Score', 'cvssMetricV31 / V30 / V2', 'Falls back across versions'],
                    ['Patch Status', 'Reference tags (Patch/Vendor Advisory)', 'Unpatched = red banner'],
                    ['Exploit Status', 'Reference tags (Exploit)', 'CISA KEV flag from cisaExploitAdd'],
                    ['Affected Systems', 'cve.configurations CPE', 'Vendor/product/version triples'],
                    ['CWE', 'cve.weaknesses', 'Displayed as purple tags'],
                ],
                'widths': [40*mm, 55*mm, FULL_W - 97*mm],
            },
        },
        {
            'title': 'Live Detections SOC Dashboard',
            'icon': '▲', 'accent': HexColor('#f97316'),
            'tagline': 'Real-time threat detection feed with WebSocket + polling fallback',
            'purpose': (
                'The SOC Live Detections module provides a real-time event stream combining '
                'backend-generated detection events (from the correlation engine) with '
                'Socket.IO WebSocket delivery. The dashboard features severity KPI counters, '
                'animated new-entry slide-ins, IOC + MITRE mapping on every event, and '
                'CSV export — all updating automatically without page refresh.'
            ),
            'features': [
                'WebSocket primary transport with 15-second polling fallback',
                'Severity-coded rows: CRITICAL (pulsing red glow), HIGH, MEDIUM, LOW, INFO',
                'Real-time KPI counters updated on every detection event',
                'Expandable row details: IOC value, MITRE technique, source system',
                'Event-rate badge (events/second) with rolling average',
                'Filters: severity, type, source, free-text search',
                'Auto-link to related campaigns and open cases',
                'CSV export with full event metadata',
            ],
            'workflow': [
                ('🔌', 'WebSocket Connect'),
                ('📥', 'Event Stream'),
                ('🎨', 'Render Feed'),
                ('🔔', 'Alert Action'),
            ],
            'use_case': (
                'During a ransomware campaign, the live feed shows 42 CRITICAL events '
                'per minute from 6 infected endpoints. The analyst clicks one event, sees '
                'it mapped to MITRE T1486 (Data Encrypted for Impact), opens the linked '
                'campaign case, and triggers the ransomware containment playbook — all '
                'without leaving the SOC dashboard.'
            ),
            'table': {
                'headers': ['Metric', 'Value'],
                'rows': [
                    ['Event Latency (WebSocket)', '< 2 seconds end-to-end'],
                    ['Polling Fallback Interval', '15 seconds (automatic)'],
                    ['Max Events Displayed', '200 per page with pagination'],
                    ['KPI Refresh Rate', 'Every detection event (real-time)'],
                    ['Supported Severity Levels', 'CRITICAL · HIGH · MEDIUM · LOW · INFO'],
                ],
                'widths': [65*mm, FULL_W - 67*mm],
            },
        },
        {
            'title': 'Threat Intelligence Module',
            'icon': '◉', 'accent': C_NEON2,
            'tagline': '25+ live CTI feeds with IOC enrichment and threat actor profiling',
            'purpose': (
                'The Threat Intelligence module aggregates, normalizes, and correlates '
                'indicators of compromise from 25+ live CTI feeds. It provides a searchable '
                'IOC database of 56,000+ indicators with full enrichment, threat actor '
                'profiles, campaign tracking, and MITRE ATT&CK integration.'
            ),
            'features': [
                'IOC database: 56,000+ indicators (IP, domain, hash, URL, email)',
                '25+ automated CTI feeds: OTX, Abuse.ch, ThreatFox, URLhaus, CISA',
                'IOC enrichment: VirusTotal, AbuseIPDB, Shodan, passive DNS',
                'Threat actor profiles with TTPs, targets, campaigns, attribution',
                'Kill Chain Visualizer mapped to MITRE ATT&CK v14',
                'Dark Web monitoring: paste sites, leak forums, ransomware blogs',
                'Geo-threat intelligence with real-time attack origin mapping',
                'IOC auto-expiry with configurable TTL and confidence scoring',
            ],
            'workflow': [
                ('📡', 'Feed Ingest'),
                ('⚡', 'Normalize'),
                ('🔗', 'Correlate'),
                ('🎯', 'Actionable Intel'),
            ],
            'use_case': (
                'An analyst observes a suspicious outbound connection to 185.220.101.47. '
                'The Threat Intel module instantly returns: Tor exit node (AbuseIPDB confidence 100%), '
                'seen in 3 active campaigns, linked to APT28 TTPs, classified as C2 infrastructure '
                'with MEDIUM-HIGH confidence. An automatic IOC match alert is raised and linked '
                'to the relevant case.'
            ),
            'table': {
                'headers': ['Feed Source', 'IOC Types', 'Update Frequency'],
                'rows': [
                    ['AlienVault OTX', 'IP, Domain, Hash, URL', 'Every 30 minutes'],
                    ['Abuse.ch (URLhaus/MalwareBazaar)', 'URL, Hash, C2 IPs', 'Real-time'],
                    ['CISA Known Exploited Vulns', 'CVE IDs', 'Daily'],
                    ['ThreatFox', 'IP, Domain, Hash', 'Hourly'],
                    ['Shodan InternetDB', 'IP vulnerabilities/ports', 'On-demand'],
                    ['Custom STIX/TAXII feeds', 'All IOC types', 'Configurable'],
                ],
                'widths': [55*mm, 55*mm, FULL_W - 112*mm],
            },
        },
        {
            'title': 'SOAR & Playbook Engine',
            'icon': '⚡', 'accent': C_NEON3,
            'tagline': 'Security Orchestration, Automation & Response with 50+ playbooks',
            'purpose': (
                'The SOAR engine executes automated response actions triggered by detection '
                'events or analyst intervention. Pre-built playbooks cover the most common '
                'incident types — ransomware containment, phishing response, account '
                'compromise, network intrusion — with full audit logging and human-in-the-loop '
                'escalation gates.'
            ),
            'features': [
                '50+ pre-built playbooks covering CRITICAL incident types',
                'Visual playbook builder with drag-and-drop step editor',
                'Conditional branching, approval gates, and SLA timers',
                'Actions: block IP, isolate host, reset password, create ticket',
                'Webhook integrations: Slack, PagerDuty, JIRA, ServiceNow, Teams',
                'Full execution audit trail with step-by-step logging',
                'Dry-run simulation mode for playbook testing',
                'What-If adversary simulation for attack path analysis',
            ],
            'workflow': [
                ('🚨', 'Detection Trigger'),
                ('📋', 'Playbook Match'),
                ('⚙️', 'Auto Execute'),
                ('📊', 'Case Update'),
            ],
            'use_case': (
                'Ransomware detected on WORKSTATION-042. The "Ransomware Response" '
                'playbook automatically: (1) isolates the host via EDR API, '
                '(2) suspends the affected user account in Active Directory, '
                '(3) creates a P1 incident case, (4) alerts the SOC Slack channel, '
                '(5) requests manager approval for full network block — all within 4 seconds.'
            ),
            'table': {
                'headers': ['Playbook', 'Trigger Condition', 'Auto Actions'],
                'rows': [
                    ['Ransomware Response', 'File encryption + C2 IOC match', 'Isolate host, suspend user, P1 case'],
                    ['Phishing Containment', 'Email IOC + credential theft alert', 'Block sender, reset password, scan mailbox'],
                    ['Account Compromise', 'Impossible travel + failed logins', 'Force MFA, alert manager, audit session'],
                    ['Network Intrusion', 'Lateral movement + port scan detected', 'Block source IP, segment VLAN, alert NOC'],
                    ['Data Exfiltration', 'Large upload + DLP trigger', 'Block destination, preserve forensics, legal hold'],
                ],
                'widths': [45*mm, 55*mm, FULL_W - 102*mm],
            },
        },
        {
            'title': 'Dark Web Monitoring',
            'icon': '◈', 'accent': HexColor('#ec4899'),
            'tagline': 'Continuous monitoring of dark web, paste sites, and leak forums',
            'purpose': (
                'The Dark Web Monitoring module provides proactive surveillance of '
                'underground forums, ransomware leak sites, paste services (Pastebin, '
                'PrivateBin), and Telegram channels for corporate credential leaks, '
                'stolen data, and threat actor communications targeting the monitored '
                'organization.'
            ),
            'features': [
                'Monitoring of 200+ dark web forums, marketplaces, and leak sites',
                'Credential exposure detection: email/password pairs, API keys',
                'Ransomware group activity tracking (LockBit, ALPHV, Cl0p, etc.)',
                'Brand and domain mention alerting on underground forums',
                'Paste site monitoring with regex-based keyword extraction',
                'Historical leak database search (Have I Been Pwned integration)',
                'Risk scoring: Critical/High/Medium based on data type and context',
                'Automated alert creation with evidence preservation',
            ],
            'workflow': [
                ('🔭', 'Monitor Sources'),
                ('🎯', 'Keyword Match'),
                ('⚠️', 'Risk Score'),
                ('📬', 'SOC Alert'),
            ],
            'use_case': (
                'The monitoring engine detects that 847 corporate email/password pairs '
                'from the target organization have appeared in a fresh dump on a known '
                'Russian-language cybercrime forum. A CRITICAL dark web alert is generated, '
                'containing the data sample hash, estimated exposure date, threat actor '
                'handle, and an automatic playbook recommendation to force password resets '
                'for all affected accounts.'
            ),
            'table': {
                'headers': ['Source Type', 'Detection Method', 'Alert Threshold'],
                'rows': [
                    ['Ransomware Leak Sites', 'Domain/company name match', 'Any mention → CRITICAL'],
                    ['Paste Services', 'Email domain + credential regex', '>5 credentials → HIGH'],
                    ['Underground Forums', 'Keyword and entity matching', 'Context-scored'],
                    ['Telegram Channels', 'Keyword monitor + bot API', 'On-match → MEDIUM+'],
                    ['Dark Web Markets', 'Product/brand scraping', 'Price threshold'],
                ],
                'widths': [45*mm, 60*mm, FULL_W - 107*mm],
            },
        },
    ]

    for i, mod in enumerate(modules):
        if i > 0:
            story.append(PageBreak())

        story.append(KeepTogether([
            Paragraph(
                f'<font color="{color_hex(mod["accent"])}">⬛</font>  '
                f'<b>{mod["title"]}</b>',
                S['H1']
            ),
            NeonHRule(neon_frac=0.25),
            Spacer(1, 1*mm),
            Paragraph(
                f'<i><font color="{color_hex(mod["accent"])}">{mod["tagline"]}</font></i>',
                S['H3']
            ),
            Spacer(1, 2*mm),
            Paragraph(mod['purpose'], S['Body']),
        ]))
        story.append(Spacer(1, 3*mm))

        # Workflow
        story.append(Paragraph('Operational Workflow', S['H2']))
        story.append(WorkflowDiagram(
            [(icon, label) for icon, label in mod['workflow']],
            height=65, accent=mod['accent']
        ))
        story.append(Spacer(1, 3*mm))

        # Features + table split
        feat_col = [bullet(f, S['Bullet']) for f in mod['features'][:4]]
        feat_col2 = [bullet(f, S['Bullet']) for f in mod['features'][4:]]

        feat_t = Table(
            [[
                Table([[p] for p in feat_col],
                      colWidths=['100%'],
                      style=TableStyle([('TOPPADDING',(0,0),(-1,-1),1),
                                        ('BOTTOMPADDING',(0,0),(-1,-1),1)])),
                Table([[p] for p in feat_col2] if feat_col2 else [[Paragraph('',S['Body'])]],
                      colWidths=['100%'],
                      style=TableStyle([('TOPPADDING',(0,0),(-1,-1),1),
                                        ('BOTTOMPADDING',(0,0),(-1,-1),1)])),
            ]],
            colWidths=[FULL_W*0.5, FULL_W*0.5],
            style=TableStyle([('VALIGN',(0,0),(-1,-1),'TOP')])
        )
        story.append(feat_t)
        story.append(Spacer(1, 3*mm))

        # Detail table
        story.append(Paragraph('Technical Details', S['H2']))
        story.append(NeonHRule(neon_frac=0.2))
        story.append(feature_table(
            mod['table']['headers'],
            mod['table']['rows'],
            S,
            col_widths=mod['table']['widths']
        ))
        story.append(Spacer(1, 3*mm))

        # Use case box
        story.append(info_box(
            f'<b><font color="{color_hex(mod["accent"])}">◈ USE CASE:</font></b>  '
            f'{mod["use_case"]}',
            accent=mod['accent'],
            style=S['Body']
        ))

    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  05  USE CASES
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('USE CASES & SOC SCENARIOS',
                               'Real-World Detection, Investigation & Response',
                               section_num='05', icon_char='◉',
                               accent=HexColor('#f97316')))
    story.append(Spacer(1, 3*mm))

    use_cases = [
        {
            'title': 'Use Case 1: Ransomware Incident Detection & Containment',
            'severity': 'CRITICAL',
            'accent': HexColor('#ef4444'),
            'scenario': (
                'A finance department endpoint begins encrypting shared drive files at 02:14 AM. '
                'No human analyst is active.'
            ),
            'steps': [
                ('Detection', 'Live detection feed identifies 847 file rename events/sec matching ransomware behavioral signature (Sigma rule: proc_creation_win_ransomware_extensions)'),
                ('Enrichment', 'RAKAY enriches the C2 IP (185.220.101.47): confirmed Tor exit node, 95% malicious VT score, linked to LockBit 3.0 campaign'),
                ('Correlation', 'Correlation engine links the event to 6 other endpoints showing similar patterns (lateral movement via SMB within 8 minutes)'),
                ('Auto-Response', 'SOAR "Ransomware Response" playbook executes: host isolation (EDR), user suspension (AD), P1 case creation, Slack alert to SOC lead'),
                ('Investigation', 'L2 analyst reviews RAKAY-generated kill chain: Initial access T1566.001 → Execution T1059.001 → Impact T1486, with suggested containment steps'),
                ('Resolution', 'All 7 hosts isolated in 4 seconds, encryption stopped. MTTR: 4 minutes vs. industry average 197 minutes'),
            ],
        },
        {
            'title': 'Use Case 2: APT Threat Hunting Campaign',
            'severity': 'HIGH',
            'accent': C_NEON3,
            'scenario': (
                'Intel suggests APT29 (Cozy Bear) is targeting financial services in the region. '
                'The SOC team initiates a proactive hunt.'
            ),
            'steps': [
                ('Threat Intel', 'Analyst queries RAKAY: "Show me APT29 TTPs and generate detection rules." RAKAY returns actor profile, 12 TTPs, and 8 Sigma rules in 6 seconds'),
                ('IOC Lookup', '28 APT29-attributed IOCs (domains, IPs, file hashes) loaded into hunt scope — 3 match against internal DNS logs from the past 14 days'),
                ('Hunt Query', 'KQL queries generated for Azure Sentinel targeting PowerShell obfuscation (T1059.001) and LSASS credential dumping (T1003.001)'),
                ('Discovery', 'Two matching events found: WORKSTATION-117 ran encoded PowerShell 9 days ago; WORKSTATION-203 had LSASS access from non-system process'),
                ('Investigation', 'RAKAY analyzes the process chain, identifies Cobalt Strike beacon signature, maps to APT29 campaign cluster 2025-FIN-07'),
                ('Remediation', 'Both hosts reimaged, credentials rotated, detection rules permanently added to ruleset, threat actor profile updated'),
            ],
        },
        {
            'title': 'Use Case 3: Zero-Day CVE Impact Assessment',
            'severity': 'CRITICAL',
            'accent': HexColor('#f59e0b'),
            'scenario': (
                'CVE-2025-44228 (critical RCE in widely-used middleware) published on NVD at 09:00 AM. '
                'Security team needs immediate impact assessment.'
            ),
            'steps': [
                ('CVE Detection', 'CVE Intelligence Engine auto-refresh detects new CRITICAL entry. CVSS 10.0, marked Unpatched, exploit PoC confirmed on GitHub'),
                ('Asset Mapping', 'Platform queries asset inventory against CVE\'s affected CPE list — 23 internal servers running vulnerable version identified'),
                ('RAKAY Analysis', 'Analyst asks RAKAY for mitigation options. RAKAY provides: WAF rule, temporary config fix, network segmentation recommendation, and monitoring Sigma rule'),
                ('Risk Scoring', 'Geo-threat map shows 847 active scanning attempts for this CVE in the last 6 hours targeting the organization\'s IP range'),
                ('Remediation Tracking', 'Case created for each affected server with patch deadline, assigned to system owners, SLA timer started (24h for critical)'),
                ('Patch Verification', 'Post-patch: CVE detection rule confirms vulnerability is no longer triggering on patched hosts. Case closed.'),
            ],
        },
    ]

    for uc in use_cases:
        story.append(KeepTogether([
            Paragraph(
                f'<font color="{color_hex(uc["accent"])}"><b>{uc["title"]}</b></font>',
                S['H2']
            ),
            NeonHRule(neon_frac=0.2),
        ]))

        sev_col = HexColor('#ef4444') if uc['severity'] == 'CRITICAL' else C_NEON3
        header = Table(
            [[
                Paragraph(f'<b><font color="{color_hex(uc["accent"])}">'
                          f'SEVERITY: {uc["severity"]}</font></b>', S['Tag']),
                Paragraph(f'<i>{uc["scenario"]}</i>', S['BodySm']),
            ]],
            colWidths=[40*mm, FULL_W - 42*mm],
            style=TableStyle([
                ('VALIGN',(0,0),(-1,-1),'TOP'),
                ('TOPPADDING',(0,0),(-1,-1),4),
                ('BOTTOMPADDING',(0,0),(-1,-1),4),
                ('BACKGROUND',(0,0),(0,-1), HexColor('#0a0f1e')),
                ('LEFTPADDING',(0,0),(0,-1), 8),
            ])
        )
        story.append(header)
        story.append(Spacer(1, 2*mm))

        for step_num, (step_title, step_desc) in enumerate(uc['steps'], 1):
            row = Table(
                [[
                    Paragraph(
                        f'<font color="{color_hex(uc["accent"])}"><b>{step_num:02d}</b></font>',
                        S['H2']
                    ),
                    Paragraph(
                        f'<b><font color="#e2e8f0">{step_title}</font></b>',
                        S['Body']
                    ),
                    Paragraph(step_desc, S['BodySm']),
                ]],
                colWidths=[12*mm, 32*mm, FULL_W - 46*mm],
                style=TableStyle([
                    ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                    ('TOPPADDING',(0,0),(-1,-1),5),
                    ('BOTTOMPADDING',(0,0),(-1,-1),5),
                    ('LINEBELOW',(0,0),(-1,-1),0.3, C_BORDER2),
                    ('BACKGROUND',(0,0),(1,-1), HexColor('#070d1a')),
                ])
            )
            story.append(row)
        story.append(Spacer(1, 5*mm))

    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  06  KEY DIFFERENTIATORS
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('KEY FEATURES & DIFFERENTIATORS',
                               'What Sets Wadjet-Eye AI Apart',
                               section_num='06', icon_char='▲', accent=C_NEON4))
    story.append(Spacer(1, 3*mm))

    story.append(ThreatMatrix(height=110))
    story.append(Paragraph(
        'Threat detection coverage matrix showing Wadjet-Eye AI\'s detection density '
        'across impact levels and probability axes.',
        S['Caption']
    ))
    story.append(Spacer(1, 4*mm))

    differentiators = [
        ('AI-Native Architecture', C_NEON, [
            'RAKAY AI analyst embedded at the core — not bolted on as an afterthought',
            'LLM tool-calling loop executes up to 5 specialized security tools per query',
            'Automatic session persistence ensures analysts never lose investigation context',
            'Model-agnostic: swap between GPT-4o, Claude 3, or custom endpoints',
        ]),
        ('Real-Time Detection at Scale', HexColor('#f97316'), [
            'Sub-2-second alert latency via WebSocket streaming',
            'Dual-transport Socket.IO (polling + WebSocket) guarantees delivery',
            'Correlation engine processes 10,000+ events/minute without degradation',
            'Automatic polling fallback ensures continuity during WS disruptions',
        ]),
        ('Enterprise SOAR Automation', C_NEON3, [
            '50+ pre-built playbooks covering every major incident category',
            'What-If adversary simulation quantifies attack path risk before incidents',
            'Human-in-the-loop escalation gates for high-consequence actions',
            'Full audit trail on every automated and manual response action',
        ]),
        ('MSSP & Multi-Tenant Ready', C_NEON2, [
            'Row-Level Security (RLS) enforces strict tenant data isolation at DB level',
            'Per-tenant RBAC with 8 granular role definitions',
            'White-label branding: custom logo, colors, and domain per customer',
            'Usage-based pricing engine with automated billing report generation',
        ]),
        ('Open Integration Ecosystem', HexColor('#ec4899'), [
            'RESTful API covering 30+ endpoint groups with Swagger documentation',
            'Native connectors: Splunk, Microsoft Sentinel, CrowdStrike, SentinelOne',
            'STIX/TAXII 2.1 support for bidirectional threat intel sharing',
            'Webhook delivery to Slack, Teams, PagerDuty, JIRA, ServiceNow',
        ]),
        ('Zero-Friction Deployment', C_NEON4, [
            'Cloud-native: Vercel (frontend) + Render (backend) — no infra management',
            'Single-click tenant provisioning with automatic DB schema migration',
            'Progressive web app: works on desktop and mobile without app install',
            'Offline-resilient: cached dashboard renders during backend cold-start',
        ]),
    ]

    # 2-col grid layout
    for i in range(0, len(differentiators), 2):
        left = differentiators[i]
        right = differentiators[i+1] if i+1 < len(differentiators) else None

        def diff_cell(d):
            title, acc, feats = d
            feat_items = [bullet(f, S['Bullet']) for f in feats]
            inner = Table(
                [[Paragraph(f'<font color="{color_hex(acc)}"><b>{title}</b></font>', S['H2'])]] +
                [[p] for p in feat_items],
                colWidths=['100%'],
                style=TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), HexColor('#0a1626')),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 10),
                    ('RIGHTPADDING', (0,0), (-1,-1), 10),
                    ('LINEABOVE', (0,0), (-1,0), 2, acc),
                    ('BOX', (0,0), (-1,-1), 0.5, HexColor('#1e3a5f')),
                ])
            )
            return inner

        row_data = [[diff_cell(left), diff_cell(right) if right else Spacer(1,1)]]
        grid = Table(
            row_data,
            colWidths=[FULL_W * 0.49, FULL_W * 0.49],
            style=TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ])
        )
        story.append(grid)

    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  07  INTEGRATION ECOSYSTEM
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('INTEGRATION ECOSYSTEM',
                               'APIs, Connectors & Enterprise Compatibility',
                               section_num='07', icon_char='◈', accent=C_NEON2))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph(
        'Wadjet-Eye AI is built for interoperability. Every platform capability is '
        'accessible via a documented REST API, with native connectors for the most '
        'widely deployed security tools and enterprise platforms.',
        S['Body']
    ))
    story.append(Spacer(1, 3*mm))

    integrations = [
        ['SIEM Platforms',
         'Microsoft Sentinel · Splunk SIEM · IBM QRadar · Elastic SIEM · Sumo Logic',
         'Bidirectional alert sync, log forwarding, detection rule push'],
        ['EDR/XDR',
         'CrowdStrike Falcon · SentinelOne · Microsoft Defender XDR · Carbon Black',
         'Host isolation commands, telemetry pull, threat intelligence enrichment'],
        ['Threat Intelligence',
         'MISP · OpenCTI · VirusTotal Enterprise · Shodan · AlienVault OTX',
         'IOC sharing, feed subscription, automated enrichment'],
        ['Ticketing & ITSM',
         'JIRA · ServiceNow · PagerDuty · Freshservice',
         'Auto case creation, status sync, SLA monitoring'],
        ['Communication',
         'Slack · Microsoft Teams · Email (SMTP/SendGrid)',
         'Real-time alerts, escalation notifications, digest reports'],
        ['Identity & Access',
         'Okta · Azure AD · Active Directory (via LDAP) · SAML 2.0 / OIDC',
         'SSO, automated account actions, group-based RBAC sync'],
        ['Cloud Security',
         'AWS GuardDuty · Azure Security Center · GCP Security Command Center',
         'Cloud-native finding ingestion and alert correlation'],
        ['Vulnerability Management',
         'Tenable.io · Qualys · Rapid7 InsightVM',
         'Scan result import, CVE cross-reference, risk prioritization'],
    ]

    story.append(feature_table(
        ['Integration Category', 'Supported Platforms', 'Integration Type'],
        integrations, S,
        col_widths=[42*mm, 80*mm, FULL_W - 124*mm]
    ))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph('API Coverage', S['H2']))
    story.append(NeonHRule(neon_frac=0.2))
    story.append(Spacer(1, 2*mm))

    api_groups = [
        ['/api/auth', 'Authentication & token management', '4'],
        ['/api/alerts', 'Alert CRUD, triage, bulk update', '12'],
        ['/api/cases', 'Case management, timeline, evidence', '15'],
        ['/api/iocs', 'IOC database, enrichment, bulk import', '10'],
        ['/api/cti', 'CTI feeds, detections, threat actors', '18'],
        ['/api/cve', 'CVE intelligence, search, statistics', '6'],
        ['/api/RAKAY', 'AI analyst chat, sessions, history', '8'],
        ['/api/soar', 'Playbooks, execution, audit', '14'],
        ['/api/dashboard', 'KPI stats, live feed, mini-reports', '7'],
        ['/api/reports', 'Report generation, templates, export', '9'],
    ]
    story.append(feature_table(
        ['Endpoint Group', 'Description', 'Routes'],
        api_groups, S,
        col_widths=[40*mm, FULL_W - 60*mm, 18*mm]
    ))
    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  08  SECURITY & COMPLIANCE
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('SECURITY & COMPLIANCE',
                               'Multi-Tenant Architecture, RBAC & Data Protection',
                               section_num='08', icon_char='◉', accent=C_NEON5))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph(
        'Security is foundational, not supplemental. Every architectural decision — '
        'from the database schema to the API authentication model — is designed with '
        'zero-trust principles, minimal privilege, and auditability as first-class requirements.',
        S['Body']
    ))
    story.append(Spacer(1, 3*mm))

    security_items = [
        ['Multi-Tenancy', 'Row-Level Security (RLS) at PostgreSQL level; tenant_id enforced on every table; service role bypasses restricted to backend only'],
        ['Authentication', 'Supabase JWT (primary) + RAKAY service key + 24h demo token; 3-tier model; failed auth logged with IP and user-agent'],
        ['Authorization', 'RBAC with 8 roles: super_admin, mssp_admin, tenant_admin, soc_manager, analyst, junior_analyst, readonly, auditor'],
        ['Data Encryption', 'TLS 1.3 in transit (Vercel/Render); AES-256 at rest (Supabase managed encryption)'],
        ['Rate Limiting', 'Global: 500 req/15min; Auth: 10 attempts/15min; Intel: 30 req/min; RAKAY demo auth: 20 req/min'],
        ['Audit Logging', 'Every mutating API request logged with user, tenant, endpoint, IP, timestamp, and response status'],
        ['CORS Policy', 'Strict allowlist (Vercel origin only in production); OPTIONS preflights handled before auth middleware'],
        ['Secret Management', 'Render environment variables; no secrets in code; JWT_SECRET rotation supported without downtime'],
        ['Input Validation', 'Joi schema validation on all POST/PUT bodies; SQL injection prevented by Supabase parameterized queries'],
        ['Vulnerability Mgmt', 'Automated npm audit in CI; weekly dependency review; CVE tracking for all direct dependencies'],
    ]

    story.append(feature_table(
        ['Control', 'Implementation'],
        security_items, S,
        col_widths=[48*mm, FULL_W - 50*mm]
    ))
    story.append(Spacer(1, 4*mm))

    story.append(info_box(
        '🔐  The platform\'s audit logging capability records every mutating action '
        '(create, update, delete) across all modules with user identity, tenant context, '
        'source IP, and timestamp — providing a complete, tamper-evident trail suitable '
        'for compliance reporting (SOC 2, ISO 27001, GDPR, NIS2).',
        accent=C_NEON5,
        style=S['Body']
    ))
    story.append(PageBreak())

    # ─────────────────────────────────────────────────────────────────────────
    #  09  CONCLUSION & ROADMAP
    # ─────────────────────────────────────────────────────────────────────────
    story.append(SectionHeader('CONCLUSION & PLATFORM ROADMAP',
                               'Strategic Value & Future Vision',
                               section_num='09', icon_char='◈', accent=C_NEON))
    story.append(Spacer(1, 3*mm))

    story.append(Paragraph(
        'Wadjet-Eye AI represents a fundamental rethinking of what a modern SOC platform '
        'should be. By natively embedding AI at every layer — from data ingestion to analyst '
        'interaction — the platform eliminates the traditional gap between raw telemetry and '
        'actionable intelligence. Security teams that previously required specialist expertise '
        'for every investigation can now leverage RAKAY\'s AI capabilities to operate at the '
        'level of senior analysts from day one.',
        S['Body']
    ))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        'The platform\'s five-layer architecture ensures that as threats evolve and data '
        'volumes grow, each layer scales independently. The open integration ecosystem '
        'means Wadjet-Eye AI enhances existing security investments rather than replacing '
        'them — feeding from SIEM platforms, enriching with threat intelligence, and '
        'pushing response actions back to EDR and SOAR tools already in use.',
        S['Body']
    ))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph('Platform Roadmap — 2026–2027', S['H2']))
    story.append(NeonHRule(neon_frac=0.3))
    story.append(Spacer(1, 2*mm))

    roadmap = [
        ['Q2 2026', 'AI-Powered Triage',
         'RAKAY autonomously triages L1 alerts, assigns severity, suggests responses, '
         'and closes clear-cut false positives without analyst intervention'],
        ['Q3 2026', 'Graph Intelligence Engine',
         'Entity relationship graph linking IOCs, threat actors, campaigns, assets, '
         'and cases for visual attack path reconstruction and lateral movement detection'],
        ['Q4 2026', 'Deception Technology Module',
         'Integrated honeypot deployment and canary token management with '
         'automatic threat actor fingerprinting on interaction'],
        ['Q1 2027', 'Autonomous Threat Hunting',
         'RAKAY-initiated hunt campaigns triggered by CTI alerts, executing pre-defined '
         'hunt playbooks across all data sources without analyst initiation'],
        ['Q2 2027', 'Compliance Automation',
         'Automated SOC 2 / ISO 27001 / NIS2 evidence collection, control mapping, '
         'and audit report generation from platform activity logs'],
        ['Q3 2027', 'Federated Intelligence Sharing',
         'Privacy-preserving IOC and TTP sharing between platform tenants via '
         'STIX/TAXII with configurable trust boundaries and anonymization'],
    ]

    story.append(feature_table(
        ['Timeline', 'Feature', 'Description'],
        roadmap, S,
        col_widths=[22*mm, 44*mm, FULL_W - 68*mm]
    ))
    story.append(Spacer(1, 5*mm))

    story.append(Paragraph('Strategic Summary', S['H2']))
    story.append(NeonHRule(neon_frac=0.3))
    story.append(Spacer(1, 2*mm))

    summary_points = [
        ('◈ Proven in Production',
         'Wadjet-Eye AI is deployed and processing live threat intelligence for real SOC teams, '
         'with 56,000+ IOCs, 25+ live feeds, and real-time detection capabilities fully operational.'),
        ('◈ AI-First, Not AI-Added',
         'RAKAY was designed as the analyst interface from the ground up — not retrofitted. '
         'Every module exposes AI-accessible context to maximize investigation quality.'),
        ('◈ Built for Growth',
         'Multi-tenant architecture, open API, and modular layer design ensure the platform '
         'scales from a 5-person SOC team to an MSSP managing hundreds of enterprise clients.'),
        ('◈ Security by Design',
         'Zero-trust principles, RLS at every data boundary, full audit logging, and '
         'RBAC enforcement make the platform suitable for the most regulated industries.'),
    ]
    for sp_title, sp_desc in summary_points:
        t = Table(
            [[
                Paragraph(f'<font color="#00d4ff"><b>{sp_title}</b></font>', S['Body']),
                Paragraph(sp_desc, S['Body']),
            ]],
            colWidths=[50*mm, FULL_W - 52*mm],
            style=TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LINEBELOW', (0,0), (-1,-1), 0.3, C_BORDER2),
                ('BACKGROUND', (0,0), (0,-1), HexColor('#080f1c')),
                ('LEFTPADDING', (0,0), (0,-1), 10),
            ])
        )
        story.append(t)

    story.append(Spacer(1, 8*mm))

    # Final CTA banner
    cta = Table(
        [[Paragraph(
            '<b><font color="#00d4ff">◉  WADJET-EYE AI</font></b><br/>'
            '<font size="9" color="#94a3b8">Enterprise SOC &amp; Threat Intelligence Platform v17.0</font><br/><br/>'
            '<font size="9" color="#e2e8f0">Frontend: </font>'
            '<font size="9" color="#00d4ff">https://wadjet-eye-ai.vercel.app</font>'
            '<font size="9" color="#64748b">  ·  </font>'
            '<font size="9" color="#e2e8f0">API: </font>'
            '<font size="9" color="#00d4ff">https://wadjet-eye-ai.onrender.com</font>',
            ParagraphStyle('CTA', fontName='Helvetica-Bold', fontSize=14,
                           leading=22, textColor=C_HEADING, alignment=TA_CENTER)
        )]],
        colWidths=[FULL_W],
        style=TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), HexColor('#070f20')),
            ('BOX', (0,0), (-1,-1), 1.5, C_NEON),
            ('TOPPADDING', (0,0), (-1,-1), 20),
            ('BOTTOMPADDING', (0,0), (-1,-1), 20),
            ('LEFTPADDING', (0,0), (-1,-1), 20),
            ('RIGHTPADDING', (0,0), (-1,-1), 20),
            ('LINEABOVE', (0,0), (-1,0), 3, C_NEON),
        ])
    )
    story.append(cta)

    # ── Build the document ────────────────────────────────────────────────────
    def first_page(canv, doc):
        draw_cover_background(canv, doc)

    def later_pages(canv, doc):
        draw_page_background(canv, doc)

    doc.build(
        story,
        onFirstPage=first_page,
        onLaterPages=later_pages,
    )
    print(f'[✓] PDF generated: {out_path}')
    return out_path


if __name__ == '__main__':
    out = build_pdf('/home/user/webapp/Wadjet-Eye-AI-Platform-Overview.pdf')
    print(f'Output: {out}')
