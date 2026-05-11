from __future__ import annotations

from pathlib import Path
import time
from typing import Dict, Iterable, List

from .models import HostSnapshot
from .storage import SQLiteStore

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except Exception:
    colors = None
    A4 = None
    Paragraph = None
    ParagraphStyle = None
    SimpleDocTemplate = None
    Spacer = None
    Table = None
    TableStyle = None
    getSampleStyleSheet = None
    mm = None


def _safe_text(value: object) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _clip(value: object, limit: int = 120) -> str:
    text = str(value or "-").replace("\r", " ").strip()
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "..."


def _compact_geoip_status(value: object) -> str:
    text = str(value or "Unknown")
    if "enabled" in text.lower():
        return "GeoIP enabled"
    if "disabled" in text.lower():
        return "GeoIP disabled"
    return _clip(text, 80)


def _collect_iocs(alerts: List[Dict[str, object]]) -> List[Dict[str, object]]:
    seen = set()
    rows: List[Dict[str, object]] = []
    for alert in alerts:
        for indicator in alert.get("iocs", []) or []:
            if indicator in seen:
                continue
            seen.add(indicator)
            rows.append(
                {
                    "indicator": indicator,
                    "classification": alert.get("classification", "Unknown"),
                    "host": alert.get("host", "-"),
                }
            )
    return rows[:40]


def list_pdf_reports(report_dir: str) -> List[Dict[str, object]]:
    directory = Path(report_dir)
    if not directory.exists():
        return []
    reports = []
    for path in sorted(directory.glob("*.pdf"), key=lambda item: item.stat().st_mtime, reverse=True):
        stats = path.stat()
        reports.append(
            {
                "name": path.name,
                "path": str(path),
                "size": stats.st_size,
                "modified_at": stats.st_mtime,
            }
        )
    return reports


class ReportGenerator:
    def __init__(self, store: SQLiteStore, report_dir: str):
        self.store = store
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        stats: Dict[str, object],
        host_rows: List[HostSnapshot],
    ) -> Dict[str, str]:
        if SimpleDocTemplate is None or Table is None or Paragraph is None:
            raise RuntimeError(
                "Proper PDF reporting requires reportlab. Install requirements.txt before generating reports."
            )

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        pdf_path = self.report_dir / f"report-{timestamp}.pdf"

        payload = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": stats,
            "severity_counts": self.store.fetch_alert_counts(),
            "top_riskiest_connections": self.store.fetch_top_riskiest(limit=10),
            "mitre_heatmap": self.store.fetch_mitre_heatmap(),
            "hosts": [row.to_dict() for row in host_rows[:20]],
            "recent_alerts": self.store.fetch_alerts(limit=40),
            "sessions": self.store.fetch_sessions(limit=20),
            "artifacts": self.store.fetch_artifacts(limit=20),
            "hunt_summary": self.store.fetch_hunt_summary(hours=24),
        }
        payload["ioc_catalog"] = _collect_iocs(payload["recent_alerts"])
        self._build_pdf(payload, pdf_path)
        return {"pdf": str(pdf_path)}

    def _styles(self):
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=26,
                textColor=colors.HexColor("#0B1F33"),
                spaceAfter=8,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ReportSection",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=16,
                textColor=colors.HexColor("#10314F"),
                spaceAfter=8,
                spaceBefore=6,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ReportBody",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=9.2,
                leading=12,
                textColor=colors.HexColor("#21364C"),
            )
        )
        styles.add(
            ParagraphStyle(
                name="ReportMeta",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=8.4,
                leading=11,
                textColor=colors.HexColor("#546A7F"),
            )
        )
        styles.add(
            ParagraphStyle(
                name="ReportTableHeader",
                parent=styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=7.8,
                leading=9.4,
                textColor=colors.white,
                wordWrap="CJK",
            )
        )
        styles.add(
            ParagraphStyle(
                name="ReportTableCell",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=7.6,
                leading=9.2,
                textColor=colors.HexColor("#203448"),
                wordWrap="CJK",
            )
        )
        return styles

    def _table(self, rows: Iterable[Iterable[object]], column_widths=None, header_fill="#102D4A") -> Table:
        styles = getattr(self, "_pdf_styles", None)
        header_style = styles["ReportTableHeader"] if styles else None
        cell_style = styles["ReportTableCell"] if styles else None
        wrapped_rows = []
        for row_index, row in enumerate(rows):
            wrapped_row = []
            for value in row:
                if Paragraph is not None and header_style is not None and cell_style is not None:
                    style = header_style if row_index == 0 else cell_style
                    text = _safe_text(value).replace("\n", "<br/>")
                    wrapped_row.append(Paragraph(text, style))
                else:
                    wrapped_row.append(value)
            wrapped_rows.append(wrapped_row)
        table = Table(wrapped_rows, colWidths=column_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_fill)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8.6),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
                    ("TOPPADDING", (0, 0), (-1, 0), 7),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FBFF")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FBFF"), colors.HexColor("#EEF4FB")]),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C9D6E4")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#203448")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 1), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                ]
            )
        )
        return table

    def _summary_table(self, payload: Dict[str, object]) -> Table:
        stats = payload["stats"]
        summary_rows = [
            ["Packets Inspected", stats.get("packets_processed", 0), "Detections Raised", stats.get("alerts_generated", 0)],
            ["Observed Hosts", stats.get("tracked_hosts", 0), "Tracked Sessions", stats.get("tracked_sessions", 0)],
            ["Threat Feeds", stats.get("ioc_count", 0), "Artifacts", len(payload.get("artifacts", []))],
        ]
        table = Table(summary_rows, colWidths=[44 * mm, 28 * mm, 44 * mm, 28 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF4FB")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D6E4")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D2DEEA")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F2941")),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        return table

    def _scope_table(self, payload: Dict[str, object]) -> Table:
        stats = payload["stats"]
        scope_rows = [
            ["Storage", stats.get("database_backend", "sqlite"), "GeoIP", _compact_geoip_status(stats.get("geoip_status", "Unknown"))],
            ["ML Model", stats.get("ml_status", "Unknown"), "Sequence Model", stats.get("sequence_model_status", "Unknown")],
        ]
        table = Table(scope_rows, colWidths=[30 * mm, 58 * mm, 30 * mm, 62 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F8FD")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D6E4")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D5E1EC")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#16314A")),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        return table

    def _decorate_page(self, canvas, doc) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(colors.HexColor("#D4E1EE"))
        canvas.setLineWidth(0.6)
        canvas.line(14 * mm, height - 10 * mm, width - 14 * mm, height - 10 * mm)
        canvas.line(14 * mm, 10 * mm, width - 14 * mm, 10 * mm)
        canvas.setFillColor(colors.HexColor("#5F748A"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(14 * mm, 6.5 * mm, "Ravynel NDR | Investigation Report")
        canvas.drawRightString(width - 14 * mm, 6.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    def _build_pdf(self, payload: Dict[str, object], path: Path) -> None:
        styles = self._styles()
        self._pdf_styles = styles
        story = []
        story.append(Paragraph("Ravynel NDR Investigation Report", styles["ReportTitle"]))
        story.append(
            Paragraph(
                f"Generated {payload['generated_at']} | GeoIP status: {_safe_text(_compact_geoip_status(payload['stats'].get('geoip_status', 'Unknown')))}",
                styles["ReportMeta"],
            )
        )
        story.append(Spacer(1, 5 * mm))
        story.append(self._summary_table(payload))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Investigation Scope", styles["ReportSection"]))
        story.append(self._scope_table(payload))
        story.append(Spacer(1, 6 * mm))

        story.append(Paragraph("Executive Summary", styles["ReportSection"]))
        hunt_summary = payload.get("hunt_summary", {})
        top_classifications = ", ".join(
            f"{item['classification']} ({item['total']})"
            for item in hunt_summary.get("top_classifications", [])[:5]
        ) or "No high-volume classifications were recorded in the active report window."
        story.append(
            Paragraph(
                _safe_text(
                    "This report summarizes live or historical network detections, host posture, "
                    f"and ATT&CK-mapped activity. Recent detections in the last {hunt_summary.get('window_hours', 24)} hours: "
                    f"{hunt_summary.get('total_recent_alerts', 0)}. Top classifications: {top_classifications}"
                ),
                styles["ReportBody"],
            )
        )
        story.append(Spacer(1, 5 * mm))

        severity_counts = payload.get("severity_counts", {})
        severity_rows = [["Severity", "Count"]] + [
            [severity, severity_counts.get(severity, 0)]
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ]
        story.append(Paragraph("Severity Distribution", styles["ReportSection"]))
        story.append(self._table(severity_rows, column_widths=[60 * mm, 28 * mm], header_fill="#8B1E3F"))
        story.append(Spacer(1, 5 * mm))

        risky_rows = [["Host", "Max Score", "Alert Count"]] + [
            [row.get("host", "-"), row.get("max_score", 0), row.get("alert_count", 0)]
            for row in payload.get("top_riskiest_connections", [])
        ]
        story.append(Paragraph("Top 10 Riskiest Connections", styles["ReportSection"]))
        story.append(self._table(risky_rows, column_widths=[95 * mm, 26 * mm, 28 * mm], header_fill="#733D12"))
        story.append(Spacer(1, 5 * mm))

        host_rows = [["Host", "Severity", "Score", "Packets", "Top Destination", "Latest Finding"]] + [
            [
                row.get("ip", "-"),
                row.get("severity", "LOW"),
                row.get("score", 0),
                row.get("packet_count", 0),
                _clip(row.get("top_destination", "-"), 64),
                _clip(row.get("last_finding", "-"), 72),
            ]
            for row in payload.get("hosts", [])
        ]
        story.append(Paragraph("Host Risk Matrix", styles["ReportSection"]))
        story.append(
            self._table(
                host_rows,
                column_widths=[36 * mm, 22 * mm, 14 * mm, 16 * mm, 46 * mm, 42 * mm],
                header_fill="#10314F",
            )
        )
        story.append(Spacer(1, 5 * mm))

        alert_rows = [["Severity", "Title", "Host", "Destination", "Technique"]] + [
            [
                alert.get("severity", "LOW"),
                _clip(alert.get("title", "-"), 72),
                _clip(alert.get("host", "-"), 72),
                _clip(alert.get("destination", "-"), 84),
                alert.get("mitre_technique", "-"),
            ]
            for alert in payload.get("recent_alerts", [])[:18]
        ]
        story.append(Paragraph("Recent Detections", styles["ReportSection"]))
        story.append(
            self._table(
                alert_rows,
                column_widths=[18 * mm, 46 * mm, 34 * mm, 54 * mm, 20 * mm],
                header_fill="#962F3F",
            )
        )
        story.append(Spacer(1, 5 * mm))

        mitre_rows = [["Tactic", "Technique", "Count"]] + [
            [item.get("mitre_tactic", "-"), item.get("mitre_technique", "-"), item.get("total", 0)]
            for item in payload.get("mitre_heatmap", [])[:18]
        ]
        story.append(Paragraph("MITRE ATT&CK Coverage", styles["ReportSection"]))
        story.append(self._table(mitre_rows, column_widths=[55 * mm, 35 * mm, 22 * mm], header_fill="#254C32"))
        story.append(Spacer(1, 5 * mm))

        artifact_rows = [["Artifact", "Content Type", "Status", "Session"]] + [
            [
                item.get("file_name") or item.get("source_url") or "artifact",
                item.get("content_type", "-"),
                item.get("status", "-"),
                item.get("session_id", "-"),
            ]
            for item in payload.get("artifacts", [])[:18]
        ]
        story.append(Paragraph("Extracted Evidence", styles["ReportSection"]))
        story.append(
            self._table(
                artifact_rows,
                column_widths=[52 * mm, 40 * mm, 28 * mm, 52 * mm],
                header_fill="#3E315D",
            )
        )
        story.append(Spacer(1, 5 * mm))

        detailed_rows = [["Severity", "Finding", "Host / Destination", "Recommended Action"]] + [
            [
                alert.get("severity", "LOW"),
                f"{_clip(alert.get('title', '-'), 68)}\n{_clip('; '.join(alert.get('reasons', [])[:2]), 180)}",
                f"{_clip(alert.get('host', '-'), 64)}\n{_clip(alert.get('destination', '-'), 82)}",
                _clip(alert.get("action", "-"), 160),
            ]
            for alert in payload.get("recent_alerts", [])[:10]
        ]
        story.append(Paragraph("Detailed Findings", styles["ReportSection"]))
        story.append(
            self._table(
                detailed_rows,
                column_widths=[18 * mm, 56 * mm, 50 * mm, 52 * mm],
                header_fill="#6D2549",
            )
        )
        story.append(Spacer(1, 5 * mm))

        ioc_rows = [["Indicator", "Classification", "Observed Host"]] + [
            [item.get("indicator", "-"), item.get("classification", "-"), item.get("host", "-")]
            for item in payload.get("ioc_catalog", [])
        ]
        if len(ioc_rows) == 1:
            ioc_rows.append(["None captured", "-", "-"])
        story.append(Paragraph("IOC Catalog", styles["ReportSection"]))
        story.append(
            self._table(
                ioc_rows,
                column_widths=[78 * mm, 52 * mm, 48 * mm],
                header_fill="#264763",
            )
        )
        story.append(Spacer(1, 5 * mm))

        remediation_rows = [["Priority", "Recommended Remediation"]] + [
            ["1", "Validate critical and high-severity detections against host role, recent change windows, and known services."],
            ["2", "Block or isolate confirmed malicious destinations and export related indicators into downstream tooling."],
            ["3", "Review session evidence, reconstructed streams, and extracted artifacts for payload staging or credential abuse."],
            ["4", "Tune baselines and ML thresholds when repeated benign traffic patterns are confirmed by investigation."],
        ]
        story.append(Paragraph("Remediation Guidance", styles["ReportSection"]))
        story.append(self._table(remediation_rows, column_widths=[18 * mm, 160 * mm], header_fill="#27533C"))

        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=14 * mm,
            rightMargin=14 * mm,
            topMargin=14 * mm,
            bottomMargin=14 * mm,
            title="Ravynel NDR Report",
            author="Ravynel NDR",
        )
        doc.build(story, onFirstPage=self._decorate_page, onLaterPages=self._decorate_page)
