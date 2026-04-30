from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Dict, List

from .models import AlertRecord, HostSnapshot
from .output import to_cef
from .storage import SQLiteStore

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except Exception:
    canvas = None
    letter = None


def _html_escape(value: object) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


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
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        json_path = self.report_dir / f"report-{timestamp}.json"
        html_path = self.report_dir / f"report-{timestamp}.html"
        cef_path = self.report_dir / f"alerts-{timestamp}.cef"
        pdf_path = self.report_dir / f"report-{timestamp}.pdf"

        recent_alerts = self.store.fetch_alerts(limit=200)
        riskiest = self.store.fetch_top_riskiest(limit=10)
        heatmap = self.store.fetch_mitre_heatmap()
        sessions = self.store.fetch_sessions(limit=50)
        event_counts = self.store.fetch_alert_counts()

        payload = {
            "generated_at": timestamp,
            "stats": stats,
            "severity_counts": event_counts,
            "top_riskiest_connections": riskiest,
            "mitre_heatmap": heatmap,
            "hosts": [row.to_dict() for row in host_rows[:20]],
            "recent_alerts": recent_alerts[:50],
            "sessions": sessions[:20],
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        cef_path.write_text(
            "\n".join(
                to_cef(AlertRecord(**alert))
                for alert in recent_alerts[:100]
            ),
            encoding="utf-8",
        )
        html_path.write_text(self._build_html(payload), encoding="utf-8")
        if canvas is not None and letter is not None:
            self._build_pdf(payload, pdf_path)

        result = {
            "json": str(json_path),
            "html": str(html_path),
            "cef": str(cef_path),
        }
        if pdf_path.exists():
            result["pdf"] = str(pdf_path)
        return result

    def _build_html(self, payload: Dict[str, object]) -> str:
        severity_counts = payload["severity_counts"]
        bars = []
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            value = severity_counts.get(severity, 0)
            bars.append(
                f"<div class='bar'><span>{severity}</span><strong>{value}</strong>"
                f"<div class='meter'><div style='width:{min(100, value * 5)}%'></div></div></div>"
            )

        host_rows = "".join(
            "<tr>"
            f"<td>{_html_escape(host['ip'])}</td>"
            f"<td>{_html_escape(host['severity'])}</td>"
            f"<td>{_html_escape(host['score'])}</td>"
            f"<td>{_html_escape(host['packet_count'])}</td>"
            f"<td>{_html_escape(host['top_destination'])}</td>"
            f"<td>{_html_escape(host['last_finding'])}</td>"
            "</tr>"
            for host in payload["hosts"]
        )

        mitre_rows = "".join(
            "<tr>"
            f"<td>{_html_escape(item['mitre_tactic'])}</td>"
            f"<td>{_html_escape(item['mitre_technique'])}</td>"
            f"<td>{_html_escape(item['total'])}</td>"
            "</tr>"
            for item in payload["mitre_heatmap"]
        )

        alert_rows = "".join(
            "<tr>"
            f"<td>{_html_escape(alert['severity'])}</td>"
            f"<td>{_html_escape(alert['title'])}</td>"
            f"<td>{_html_escape(alert['host'])}</td>"
            f"<td>{_html_escape(alert['destination'])}</td>"
            f"<td>{_html_escape(alert['mitre_technique'])}</td>"
            "</tr>"
            for alert in payload["recent_alerts"]
        )

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Threat Platform Report</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #06131f; color: #edf2f7; margin: 0; }}
    header {{ padding: 32px; background: linear-gradient(120deg, #0d2136, #123b5d); }}
    main {{ padding: 24px; display: grid; gap: 24px; }}
    section {{ background: rgba(15, 23, 42, 0.9); border: 1px solid #1f3650; border-radius: 16px; padding: 20px; }}
    h1, h2 {{ margin-top: 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
    .stat {{ padding: 16px; border-radius: 12px; background: #0b1c2e; }}
    .bar {{ margin-bottom: 12px; }}
    .meter {{ height: 10px; background: #16324c; border-radius: 999px; overflow: hidden; margin-top: 6px; }}
    .meter div {{ height: 100%; background: linear-gradient(90deg, #f97316, #dc2626); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #1e3348; text-align: left; vertical-align: top; }}
    th {{ color: #93c5fd; }}
  </style>
</head>
<body>
  <header>
    <h1>Advanced Network Threat Detection Report</h1>
    <p>Generated at {payload['generated_at']}</p>
  </header>
  <main>
    <section>
      <h2>Executive Summary</h2>
      <div class="grid">
        <div class="stat"><strong>Total Packets</strong><div>{_html_escape(payload['stats'].get('packets_processed', 0))}</div></div>
        <div class="stat"><strong>Total Alerts</strong><div>{_html_escape(payload['stats'].get('alerts_generated', 0))}</div></div>
        <div class="stat"><strong>Top Hosts</strong><div>{_html_escape(len(payload['hosts']))}</div></div>
        <div class="stat"><strong>Stored Sessions</strong><div>{_html_escape(len(payload['sessions']))}</div></div>
      </div>
    </section>
    <section>
      <h2>Severity Distribution</h2>
      {''.join(bars)}
    </section>
    <section>
      <h2>Top 10 Riskiest Connections</h2>
      <table>
        <thead><tr><th>Host</th><th>Max Score</th><th>Alert Count</th></tr></thead>
        <tbody>
          {''.join(f"<tr><td>{_html_escape(row['host'])}</td><td>{_html_escape(row['max_score'])}</td><td>{_html_escape(row['alert_count'])}</td></tr>" for row in payload['top_riskiest_connections'])}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Host Risk Table</h2>
      <table>
        <thead><tr><th>Host</th><th>Severity</th><th>Score</th><th>Packets</th><th>Top Destination</th><th>Latest Finding</th></tr></thead>
        <tbody>{host_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>MITRE ATT&amp;CK Coverage</h2>
      <table>
        <thead><tr><th>Tactic</th><th>Technique</th><th>Count</th></tr></thead>
        <tbody>{mitre_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Recent Alerts</h2>
      <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Destination</th><th>MITRE</th></tr></thead>
        <tbody>{alert_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""

    def _build_pdf(self, payload: Dict[str, object], path: Path) -> None:
        pdf = canvas.Canvas(str(path), pagesize=letter)
        width, height = letter
        y = height - 50
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(40, y, "Advanced Network Threat Detection Report")
        y -= 30
        pdf.setFont("Helvetica", 10)
        for line in [
            f"Generated at: {payload['generated_at']}",
            f"Total packets: {payload['stats'].get('packets_processed', 0)}",
            f"Total alerts: {payload['stats'].get('alerts_generated', 0)}",
        ]:
            pdf.drawString(40, y, line)
            y -= 14
        y -= 10
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(40, y, "Top 10 Riskiest Connections")
        y -= 18
        pdf.setFont("Helvetica", 10)
        for row in payload["top_riskiest_connections"]:
            pdf.drawString(40, y, f"{row['host']} | max score={row['max_score']} | alerts={row['alert_count']}")
            y -= 14
            if y < 60:
                pdf.showPage()
                y = height - 50
        pdf.save()
