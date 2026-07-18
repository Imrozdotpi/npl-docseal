"""
pdf_generator.py
----------------
Generates a professional calibration certificate PDF that closely matches
the CSIR-NPL certificate layout from the uploaded sample.

Layout (top → bottom)
──────────────────────
  ① Header banner: NPL logos + lab name (navy bg, white text)
  ② Thin rule
  ③ "Calibration Certificate" title bar (navy bg)
  ④ Info table: key / value rows (Calibrated for … Methodology)
  ⑤ "1. Results" heading
  ⑥ Results table: dynamic rows from XML
  ⑦ Uncertainty note paragraph
  ⑧ Horizontal rule
  ⑨ Disclaimer italic line

The template is FIXED; only the content comes from the parsed dict.
"""

import os
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, HRFlowable,
)
from reportlab.platypus import NextPageTemplate

# Logo file paths, resolved relative to this module's own location so
# generation works regardless of the server process's cwd.
_ASSETS_DIR = Path(__file__).parent / "assets"
LOGO_LEFT:  str = str(_ASSETS_DIR / "CSIR_Logo.jpg")
LOGO_RIGHT: str = str(_ASSETS_DIR / "NPL_Logo.png")

# ── Page geometry ────────────────────────────────────────────────────────────
PW, PH = A4
LM = RM = 18 * mm
TM = BM = 15 * mm
HEADER_H = 30 * mm          # height of the navy banner
CONTENT_TOP = TM + HEADER_H + 3 * mm

# ── Colour palette ───────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#1a3a5c")
LIGHT_BLUE  = colors.HexColor("#d0dce8")   # table header fill
KEY_BG      = colors.HexColor("#eef2f6")   # left column of info table
ALT_BG      = colors.HexColor("#f5f8fb")   # alternate row tint
GRID_COL    = colors.HexColor("#a0b4c8")
WHITE       = colors.white
DARK        = colors.HexColor("#1a1a2e")
MID_GREY    = colors.HexColor("#555555")

USABLE_W    = PW - LM - RM


# ── Style factory ────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    S: dict[str, ParagraphStyle] = {}

    def ps(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    S["hdr_org"]   = ps("hdr_org",   fontName="Helvetica-Bold",   fontSize=11,
                         textColor=WHITE, alignment=TA_CENTER, leading=15)
    S["hdr_addr"]  = ps("hdr_addr",  fontName="Helvetica",        fontSize=8,
                         textColor=WHITE, alignment=TA_CENTER, leading=11)
    S["title"]     = ps("title",     fontName="Helvetica-Bold",   fontSize=14,
                         textColor=WHITE, alignment=TA_CENTER)
    S["key"]       = ps("key",       fontName="Helvetica-Bold",   fontSize=9,
                         textColor=DARK,  alignment=TA_LEFT,   leading=13)
    S["val"]       = ps("val",       fontName="Helvetica",        fontSize=9,
                         textColor=DARK,  alignment=TA_LEFT,   leading=13)
    S["tbl_hdr"]   = ps("tbl_hdr",   fontName="Helvetica-Bold",   fontSize=9,
                         textColor=DARK,  alignment=TA_CENTER, leading=13)
    S["tbl_cell"]  = ps("tbl_cell",  fontName="Helvetica",        fontSize=9,
                         textColor=DARK,  alignment=TA_CENTER, leading=13)
    S["sec_title"] = ps("sec_title", fontName="Helvetica-Bold",   fontSize=10,
                         textColor=DARK,  spaceBefore=5, spaceAfter=3)
    S["note"]      = ps("note",      fontName="Helvetica",        fontSize=8.5,
                         textColor=DARK,  leading=13)
    S["disclaimer"]= ps("disclaimer",fontName="Helvetica-Oblique",fontSize=7.5,
                         textColor=MID_GREY, alignment=TA_CENTER, leading=11)
    return S


# ── Canvas callbacks (header + footer drawn outside Platypus flow) ───────────

def _draw_first_page(canvas, doc, data):
    """
    Draw only on the FIRST page.
    """
    canvas.saveState()

    # Draw the top CSIR/NPL banner
    _draw_header_banner(canvas, data)

    # Do NOT draw footer here

    canvas.restoreState()


def _draw_later_pages(canvas, doc):
    """
    Draw on pages 2, 3, 4...
    Leave empty so there is no repeated header/footer.
    """
    canvas.saveState()

    # Intentionally left blank

    canvas.restoreState()


def _logo_box(canvas, x, y, w, h, path: str) -> None:
    """Draw logo image or a white placeholder rectangle."""
    if path and os.path.isfile(path):
        canvas.drawImage(path, x, y, width=w, height=h,
                         preserveAspectRatio=True, mask="auto")
    else:
        canvas.setStrokeColor(WHITE)
        canvas.setFillColor(colors.HexColor("#ffffff22"))
        canvas.roundRect(x, y, w, h, 3, fill=1, stroke=1)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawCentredString(x + w / 2, y + h / 2 - 3, "LOGO")


def _draw_header_banner(canvas, data: dict[str, Any]) -> None:
    banner_y = PH - TM - HEADER_H

    # Navy rectangle
    canvas.setFillColor(NAVY)
    canvas.rect(LM, banner_y, USABLE_W, HEADER_H, fill=1, stroke=0)

    # Bottom rule of banner
    canvas.setStrokeColor(GRID_COL)
    canvas.setLineWidth(1)
    canvas.line(LM, banner_y, LM + USABLE_W, banner_y)

    logo_w = logo_h = 22 * mm
    logo_y = banner_y + (HEADER_H - logo_h) / 2

    # Left logo
    _logo_box(canvas, LM + 3*mm, logo_y, logo_w, logo_h, LOGO_LEFT)

    # Right logo
    _logo_box(canvas, LM + USABLE_W - logo_w - 3*mm, logo_y,
              logo_w, logo_h, LOGO_RIGHT)

    # Centre text
    cx = PW / 2
    org = data.get("organization", "National Physical Laboratory")
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawCentredString(cx, banner_y + HEADER_H - 9*mm,  org)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(cx, banner_y + HEADER_H - 14*mm, "Dr. K S Krishnan Marg")
    canvas.drawCentredString(cx, banner_y + HEADER_H - 19*mm, "New Delhi – 110012, India")


def _draw_footer(canvas, doc) -> None:
    y = BM - 5*mm
    canvas.setStrokeColor(GRID_COL)
    canvas.setLineWidth(0.5)
    canvas.line(LM, y, LM + USABLE_W, y)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MID_GREY)
    canvas.drawCentredString(PW / 2, y - 4*mm, f"Page {doc.page}")


# ── Table builders ───────────────────────────────────────────────────────────

def _title_bar(S: dict) -> Table:
    tbl = Table(
        [[Paragraph("Calibration Certificate", S["title"])]],
        colWidths=[USABLE_W],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    return tbl


def _info_table(rows: list[tuple[str, str]], S: dict) -> Table:
    """Two-column key-value table matching the NPL certificate style."""
    key_w = USABLE_W * 0.36
    val_w = USABLE_W * 0.64
    data = [
        [Paragraph(k, S["key"]), Paragraph(v, S["val"])]
        for k, v in rows
    ]
    tbl = Table(data, colWidths=[key_w, val_w])
    tbl.setStyle(TableStyle([
        # Key column background
        ("BACKGROUND",    (0,0), (0,-1), KEY_BG),
        # Alternating value column tint
        ("ROWBACKGROUNDS",(1,0), (1,-1), [WHITE, ALT_BG]),
        ("GRID",          (0,0), (-1,-1), 0.5, GRID_COL),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
    ]))
    return tbl


def _results_table(results: list[dict[str, str]], S: dict) -> Table:
    """Dynamic measurement results table."""
    col_w = USABLE_W / 3
    header = [
        Paragraph("Indicated Value by<br/>Clamp Meter (A)", S["tbl_hdr"]),
        Paragraph("Measured Value (A)",                     S["tbl_hdr"]),
        Paragraph("Expanded Uncertainty<br/>in Measurement (%)", S["tbl_hdr"]),
    ]
    body = [
        [
            Paragraph(r.get("indicated_value", "N/A"), S["tbl_cell"]),
            Paragraph(r.get("measured_value",  "N/A"), S["tbl_cell"]),
            Paragraph(r.get("uncertainty",     "N/A"), S["tbl_cell"]),
        ]
        for r in results
    ]
    tbl = Table([header] + body, colWidths=[col_w, col_w, col_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), LIGHT_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, ALT_BG]),
        ("GRID",          (0,0), (-1,-1), 0.5, GRID_COL),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
    ]))
    return tbl


# ── Helper: build a safe paragraph (skip if value is N/A / empty) ────────────

def _safe(val: str, fallback: str = "N/A") -> str:
    v = (val or "").strip()
    return v if v and v != "N/A" else fallback


# ── Public API ───────────────────────────────────────────────────────────────

def generate_pdf(data: dict[str, Any], output_path: str) -> None:
    """
    Generate a professional calibration certificate PDF.

    Parameters
    ----------
    data : dict
        Normalised dict from core.xml_parser.parse_xml().
    output_path : str
        Destination .pdf file path.
    """
    S = _styles()

    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=CONTENT_TOP,
        bottomMargin=BM + 6*mm,
        title="Calibration Certificate",
        author=data.get("organization", "NPL"),
    )

    # First page frame (below header)
    first_frame = Frame(
    LM,
    BM + 6 * mm,
    USABLE_W,
    PH - CONTENT_TOP - BM - 6 * mm,
    id="first_frame",
    )

# Remaining pages (use full page height)
    later_frame = Frame(
    LM,
    BM + 6 * mm,
    USABLE_W,
    PH - TM - BM - 6 * mm,
    id="later_frame",
    )
    doc.addPageTemplates([
    PageTemplate(
        id="first",
        frames=[first_frame],
        onPage=lambda canvas, doc: _draw_first_page(canvas, doc, data),
    ),
    PageTemplate(
        id="later",
        frames=[later_frame],
        onPage=_draw_later_pages,
    ),
    ])

    # ── Story ────────────────────────────────────────────────────────────────
    story = []
    story.append(NextPageTemplate("later"))

    # ① Title bar
    story.append(_title_bar(S))
    story.append(Spacer(1, 4*mm))

    # ② Info table: build rows, omitting fields absent from the XML
    instr = data.get("instrument", {})
    env   = data.get("environment", {})

    # Instrument description cell (multi-line)
    instr_lines = []
    if _safe(instr.get("model","")) != "N/A":
        instr_lines.append(instr["model"])
    if _safe(instr.get("model_number","")) != "N/A":
        instr_lines.append(f"Model No.: {instr['model_number']},  S. No. {instr.get('serial_number','')}")
    if _safe(instr.get("range","")) != "N/A":
        instr_lines.append(f"Current: {instr['range']}")
    if _safe(instr.get("voltage","")) != "N/A":
        instr_lines.append(f"Voltage: {instr['voltage']}")
    if _safe(instr.get("make","")) != "N/A":
        instr_lines.append(f"Make: {instr['make']}")
    instr_text = "<br/>".join(instr_lines) if instr_lines else "N/A"

    # Standards text
    stds = data.get("standards", [])
    stds_clean = [s for s in stds if s and s != "N/A"]
    if stds_clean:
        roman = ["i)", "ii)", "iii)", "iv)", "v)", "vi)"]
        stds_text = "<br/>".join(
            f"{roman[i] if i < len(roman) else str(i+1)+')'} {s}"
            for i, s in enumerate(stds_clean)
        )
    else:
        stds_text = None   # will be skipped

    # Env conditions
    temp = _safe(env.get("temperature",""))
    rh   = _safe(env.get("relative_humidity",""))
    env_text = None
    if temp != "N/A" or rh != "N/A":
        env_text = (f"Temperature : {temp}" +
                    (f"<br/>Relative Humidity: {rh}" if rh != "N/A" else ""))

    # Build rows, skipping those whose value is None (field absent in XML)
    def row(key, val):
        return (key, val) if val is not None else None

    candidate_rows = [
        row("Calibrated for",
            _safe(data.get("organization",""))),
        row("Certificate No.",
            _safe(data.get("certificate_number",""))),
        row("Model",
            instr_text),
        row("Environmental Conditions",
            env_text),
        row("Standards used &amp; Associated uncertainty",
            stds_text),
        row("Traceability of Standards used",
            _safe(data.get("traceability",""), fallback=None)),
        row("Calibration Date",
            _safe(data.get("calibration_date",""), fallback=None)),
        row("Date of Issue",
            _safe(data.get("date_of_issue",""), fallback=None)),
        row("Principle / Methodology of Calibration",
            _safe(data.get("methodology",""), fallback=None)),
    ]

    info_rows = [(k, v) for item in candidate_rows
                 if item is not None
                 for k, v in [item]
                 if v is not None]

    story.append(_info_table(info_rows, S))
    story.append(Spacer(1, 5*mm))

    # ③ Results
    results = data.get("results", [])
    if results:
        story.append(Paragraph("1. Results", S["sec_title"]))
        story.append(_results_table(results, S))
        story.append(Spacer(1, 4*mm))

        note = (
            "The expanded uncertainty of our measurements at a coverage factor "
            "<b>k = 2</b>, which corresponds to a coverage probability of "
            "approximately <b>95 %</b> for a normal distribution is indicated "
            "against each value in the above table."
        )
        story.append(Paragraph(note, S["note"]))

    # ④ Remarks
    remarks = (data.get("remarks","") or "").strip()
    if remarks and remarks != "N/A":
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph(remarks, S["note"]))

    # ⑤ Rule + disclaimer
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width=USABLE_W, thickness=0.5,
                             color=GRID_COL, spaceAfter=4*mm))
    story.append(Paragraph(
        "This is a prototype certificate with notional calibration of clamp meter is shown. "
        "The actual certificate of NPLI may defer from this.",
        S["disclaimer"],
    ))

    doc.build(story)
