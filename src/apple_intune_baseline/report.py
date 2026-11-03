"""Export device_results as a PDF report and a CSV (one row per Mac and check)."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from .results import rows

CSV_FIELDS = ["device", "serial", "user", "os", "device_compliance", "last_sync", "policy", "section",
              "policy_state", "last_reported", "stale", "rule", "title", "result"]


def _t(text: str | None) -> str:
    if not text:
        return "–"
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return text


def write_csv(data: dict[str, Any], path: Path) -> Path:
    with path.open("w", newline="", encoding="utf-8-sig") as f:  # BOM: Excel opens UTF-8 correctly
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows(data):
            w.writerow({k: r.get(k, "") for k in CSV_FIELDS})
    return path


def write_pdf(data: dict[str, Any], path: Path, *, title: str, tenant: str, baseline: str) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=18, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], fontSize=10.5, spaceBefore=6, spaceAfter=2)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=8.5, leading=11, alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#555555"))
    ink, line, head_bg = colors.HexColor("#1f2933"), colors.HexColor("#d5dbe1"), colors.HexColor("#eef2f5")
    ok, bad, warn = colors.HexColor("#1a7f37"), colors.HexColor("#b42318"), colors.HexColor("#b54708")

    def p(text: Any, style=body) -> Paragraph:
        return Paragraph(escape(str(text if text not in (None, "") else "–")), style)

    def state(text: str | None) -> Paragraph:
        t = str(text or "–")
        color = ok if t.lower() in ("compliant", "success") else bad if t.lower() in (
            "noncompliant", "fail", "failed", "error") else warn
        return Paragraph(f'<font color="{color.hexval()}"><b>{escape(t)}</b></font>', body)

    def table(head: list[str], data_rows: list[list[Any]], widths: list[float]) -> Table:
        t = Table([[p(h, small) for h in head]] + data_rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), head_bg),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, line),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    width = A4[0] - 30 * mm
    s = data["summary"]
    story: list[Any] = [
        Paragraph(escape(title), h1),
        p(f"Tenant: {tenant}   ·   Baseline: {baseline}   ·   Generated: {_t(data['generated_at'])}", small),
        Spacer(1, 6),
        table(["Macs", "Compliant", "With failing checks", "Stale results"],
              [[p(s["devices"]), p(s["compliant"]), p(s["with_failures"]), p(s["stale_results"])]],
              [width / 4] * 4),
    ]
    if s["stale_results"]:
        story.append(p("Stale: Intune's result is older than the last remediation run or a day old. Intune keeps "
                       "the previous result until the discovery script runs again; 'Check status' in Company "
                       "Portal refreshes it.", small))
    if s["top_failing"]:
        story += [Paragraph("Most failing checks", h2),
                  table(["Rule", "Title", "Macs"],
                        [[p(r["rule"], small), p(r["title"]), p(r["devices"])] for r in s["top_failing"]],
                        [width * 0.38, width * 0.52, width * 0.10])]
    story += [Paragraph("Policies and scripts", h2),
              Paragraph("<b>Compliance</b><br/>" + ("<br/>".join(escape(n) for n in data["policies"])
                                                     or "none found"), small),
              Spacer(1, 3),
              Paragraph("<b>Remediation</b><br/>" + ("<br/>".join(escape(n) for n in data["scripts"])
                                                      or "none found"), small)]

    for i, d in enumerate(data["devices"]):
        story.append(PageBreak() if i == 0 else Spacer(1, 10))
        block: list[Any] = [
            Paragraph(escape(str(d["device"])), h2),
            p(f"Serial {d['serial'] or '–'}  ·  {d['model'] or ''}  ·  macOS {d['os'] or '–'}  ·  "
              f"{d['user'] or 'no user'}  ·  last check-in {_t(d['last_sync'])}", small),
            Spacer(1, 3),
            table(["Section", "State", "Checks", "Failing", "Last reported", "Note"],
                  [[p(r["section"]), state(r["state"]), p(r["checks"]), p(len(r["failing"])),
                    p(_t(r["last_reported"]), small), p(r.get("stale", ""), small)] for r in d["policies"]],
                  [width * 0.20, width * 0.15, width * 0.09, width * 0.09, width * 0.20, width * 0.27]),
        ]
        story.append(KeepTogether(block))
        failing = [(r["section"], f) for r in d["policies"] for f in r["failing"]]
        if failing:
            story += [Paragraph("Failing checks", h3),
                      table(["Section", "Rule", "Title"],
                            [[p(sec), p(f["rule"], small), p(f["title"])] for sec, f in failing],
                            [width * 0.18, width * 0.37, width * 0.45])]
        if d["remediation"]:
            story += [Paragraph("Remediation", h3),
                      table(["Section", "Run", "When", "Result"],
                            [[p(r["section"]), state(r["state"]), p(_t(r["at"]), small), p(str(r["result"]).replace(",", ", "), small)]
                             for r in d["remediation"]],
                            [width * 0.18, width * 0.12, width * 0.20, width * 0.50])]
    if data.get("not_shown"):
        story.append(p(f"{data['not_shown']} more Macs not shown (max_devices).", small))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(ink)
        canvas.drawString(15 * mm, 10 * mm, f"{title} · apple-intune-baseline (mSCP)")
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=18 * mm, title=title, author="apple-intune-baseline")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return path


TEMPLATE = Path(__file__).parent / "templates" / "dashboard.html"


def write_html(data: dict[str, Any], path: Path, *, title: str, tenant: str, baseline: str) -> Path:
    """A self-contained interactive dashboard: no external scripts, fonts or requests."""
    import json

    payload = {**data, "meta": {"title": title, "tenant": tenant, "baseline": baseline}}
    # Inside <script type="application/json">: only "</" could end the block early.
    blob = json.dumps(payload, ensure_ascii=False, default=str).replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8").replace("__TITLE__", escape(title)).replace("__DATA__", blob)
    path.write_text(html, encoding="utf-8")
    return path


INVENTORY_TEMPLATE = Path(__file__).parent / "templates" / "inventory.html"


def write_inventory_html(data: dict[str, Any], path: Path, *, title: str, tenant: str, baseline: str) -> Path:
    """Self-contained inventory report; shares the dashboard's stylesheet so both look alike."""
    import json
    import re

    style = re.search(r"<style>.*?</style>", TEMPLATE.read_text(encoding="utf-8"), re.S).group(0)
    payload = {**data, "meta": {"title": title, "tenant": tenant, "baseline": baseline}}
    blob = json.dumps(payload, ensure_ascii=False, default=str).replace("</", "<\\/")
    html = (INVENTORY_TEMPLATE.read_text(encoding="utf-8").replace("__STYLE__", style)
            .replace("__TITLE__", escape(title)).replace("__DATA__", blob))
    path.write_text(html, encoding="utf-8")
    return path
