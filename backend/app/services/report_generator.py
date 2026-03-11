"""
DarkShield Report Generator - PDF export via WeasyPrint.
Compiles audit findings into a professional dark pattern report.
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("darkshield.report")

# Category display names
CATEGORY_LABELS = {
    "asymmetric_choice": "Asymmetric Choice",
    "confirmshaming": "Confirmshaming",
    "forced_consent": "Forced Consent",
    "hidden_costs": "Hidden Costs",
    "interface_interference": "Interface Interference",
    "misdirection": "Misdirection",
    "nagging": "Nagging",
    "obstruction": "Obstruction",
    "sneaking": "Sneaking",
    "urgency": "Urgency",
}

SEVERITY_COLORS = {
    "low": "#22c55e",
    "medium": "#f59e0b",
    "high": "#ef4444",
    "critical": "#dc2626",
}

def generate_report_html(audit_data: dict) -> str:
    """Generate styled HTML report from audit data."""

    target_url = audit_data.get("target_url", "Unknown")
    risk_score = audit_data.get("risk_score", 0)
    total_patterns = audit_data.get("total_patterns", 0)
    scenarios = audit_data.get("scenarios", [])
    classifications = audit_data.get("classifications", [])
    started = audit_data.get("started_at", "")
    completed = audit_data.get("completed_at", "")

    # Risk level
    if risk_score >= 7:
        risk_level, risk_color = "Critical", "#dc2626"
    elif risk_score >= 4:
        risk_level, risk_color = "High", "#ef4444"
    elif risk_score >= 2:
        risk_level, risk_color = "Medium", "#f59e0b"
    else:
        risk_level, risk_color = "Low", "#22c55e"

    # Classification lookup
    class_map = {c.get("pattern_id", ""): c for c in classifications}

    # Severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    all_patterns = []
    for s in scenarios:
        for p in s.get("patterns_found", []):
            sev = p.get("severity", "medium")
            if sev in sev_counts:
                sev_counts[sev] += 1
            p["_scenario"] = s.get("scenario_name", "")
            all_patterns.append(p)

    # Category counts
    cat_counts = {}
    for p in all_patterns:
        cat = p.get("category", "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # Build pattern rows
    pattern_rows = ""
    for i, p in enumerate(all_patterns, 1):
        pid = p.get("pattern_id", "")
        c = class_map.get(pid, {})
        sev = c.get("severity", p.get("severity", "medium"))
        cat = c.get("category", p.get("category", "unknown"))
        desc = c.get("description", p.get("description", ""))
        evidence = c.get("evidence_summary", p.get("evidence", ""))
        confidence = c.get("confidence", p.get("confidence", 0))
        reasoning = c.get("explanation", "")
        oecd = c.get("oecdreference", "")
        remediation = c.get("remediation", "")

        oecd_html = f"<p>{oecd}</p>" if oecd else ""

        remediation_html = f"<p>{remediation}</p>" if remediation else ""

        pattern_rows += f"""
        <div class="pattern-card">
            <div class="pattern-header-row">
                <span class="pattern-num">#{i}</span>
                <span class="sev-badge" style="background:{SEVERITY_COLORS.get(sev, '#888')}">{sev.upper()}</span>
                <span class="cat-label">{CATEGORY_LABELS.get(cat, cat)}</span>
                <span class="scenario-label">{p.get('_scenario', '').replace('_', ' ').title()}</span>
                <span class="confidence-label">{int(confidence * 100)}% confidence</span>
            </div>
            <p class="pattern-desc">{desc}</p>
            <div class="evidence-box">
                <strong>Evidence:</strong> {evidence}
            </div>
            {f'<div class="reasoning"><strong>AI Reasoning:</strong> {reasoning}</div>' if reasoning else ''}
            {oecd_html}
            {remediation_html}
        </div>
        """

    # Category breakdown rows
    cat_rows = ""
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        pct = round(count / max(total_patterns, 1) * 100)
        cat_rows += f"""
        <tr>
            <td>{CATEGORY_LABELS.get(cat, cat)}</td>
            <td>{count}</td>
            <td>
                <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:#6366f1"></div></div>
            </td>
        </tr>"""

    # Scenario summary rows
    scenario_rows = ""
    for s in scenarios:
        pcount = len(s.get("patterns_found", []))
        scenario_rows += f"""
        <tr>
            <td>{s.get('scenario_name', '').replace('_', ' ').title()}</td>
            <td>{pcount}</td>
            <td>{s.get('steps_taken', 0)}</td>
            <td>{s.get('duration_seconds', 0)}s</td>
            <td>{'Pass' if s.get('success') else 'Fail'}</td>
        </tr>"""

    # OECD compliance score (inverse of risk)
    compliance_score = max(0, round((10 - risk_score) * 10))

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    @page {{ margin: 1.5cm; size: A4; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #1e1b4b; font-size: 11px; line-height: 1.5; }}

    .cover {{ text-align: center; padding: 60px 0 40px; border-bottom: 3px solid #6366f1; margin-bottom: 30px; }}
    .cover h1 {{ font-size: 32px; color: #312e81; margin-bottom: 8px; }}
    .cover .subtitle {{ font-size: 14px; color: #6366f1; }}
    .cover .url {{ font-size: 16px; margin-top: 20px; color: #4338ca; word-break: break-all; }}
    .cover .date {{ font-size: 11px; color: #64748b; margin-top: 8px; }}

    .risk-section {{ display: flex; gap: 20px; margin-bottom: 30px; }}
    .risk-circle {{ width: 100px; height: 100px; border-radius: 50%; border: 6px solid {risk_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }}
    .risk-num {{ font-size: 28px; font-weight: 800; color: {risk_color}; }}
    .risk-max {{ font-size: 11px; color: #94a3b8; }}
    .risk-details {{ flex: 1; }}
    .risk-details h2 {{ color: {risk_color}; font-size: 18px; margin-bottom: 4px; }}
    .risk-details p {{ color: #475569; }}

    .sev-summary {{ display: flex; gap: 12px; margin: 16px 0 30px; }}
    .sev-pill {{ padding: 6px 14px; border-radius: 20px; color: white; font-weight: 600; font-size: 12px; }}

    h3 {{ font-size: 16px; color: #312e81; margin: 24px 0 12px; border-bottom: 2px solid #e0e7ff; padding-bottom: 4px; }}

    table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
    th {{ background: #eef2ff; color: #312e81; text-align: left; padding: 8px 10px; font-size: 11px; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #e2e8f0; font-size: 11px; }}
    tr:nth-child(even) {{ background: #f8fafc; }}

    .bar-track {{ width: 100%; height: 8px; background: #e2e8f0; border-radius: 4px; }}
    .bar-fill {{ height: 100%; border-radius: 4px; }}

    .pattern-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 14px; page-break-inside: avoid; }}
    .pattern-header-row {{ display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }}
    .pattern-num {{ font-weight: 700; color: #6366f1; }}
    .sev-badge {{ color: white; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; }}
    .cat-label {{ font-weight: 600; color: #312e81; }}
    .scenario-label {{ color: #64748b; font-size: 10px; }}
    .confidence-label {{ color: #94a3b8; font-size: 10px; margin-left: auto; }}
    .pattern-desc {{ margin-bottom: 8px; color: #334155; }}
    .evidence-box {{ background: #f1f5f9; padding: 8px 12px; border-radius: 6px; margin-bottom: 8px; color: #475569; }}
    .reasoning {{ color: #64748b; font-style: italic; margin-bottom: 8px; }}
    .oecd-ref {{ background: #eef2ff; padding: 8px 12px; border-radius: 6px; margin-bottom: 8px; font-size: 10px; color: #4338ca; }}
    .remediation {{ margin-top: 8px; }}
    .remediation ul {{ padding-left: 20px; color: #16a34a; }}
    .remediation li {{ margin-bottom: 3px; }}

    .compliance {{ text-align: center; padding: 20px; background: #f0fdf4; border-radius: 8px; margin: 20px 0; }}
    .compliance-score {{ font-size: 36px; font-weight: 800; color: {'#16a34a' if compliance_score >= 70 else '#f59e0b' if compliance_score >= 40 else '#dc2626'}; }}

    .footer {{ text-align: center; color: #94a3b8; font-size: 9px; margin-top: 30px; padding-top: 10px; border-top: 1px solid #e2e8f0; }}
</style>
</head>
<body>

<div class="cover">
    <h1>DarkShield Audit Report</h1>
    <div class="subtitle">AI-Powered Dark Pattern Detection</div>
    <div class="url">{target_url}</div>
    <div class="date">Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}</div>
</div>

<div class="risk-section">
    <div class="risk-circle">
        <span class="risk-num">{risk_score}</span>
        <span class="risk-max">/10</span>
    </div>
    <div class="risk-details">
        <h2>{risk_level} Risk</h2>
        <p>{total_patterns} dark patterns detected across {len(scenarios)} scenarios</p>
        <p>Audit: {started[:19] if started else 'N/A'} to {completed[:19] if completed else 'N/A'}</p>
    </div>
</div>

<div class="sev-summary">
    <span class="sev-pill" style="background:{SEVERITY_COLORS['critical']}">Critical: {sev_counts['critical']}</span>
    <span class="sev-pill" style="background:{SEVERITY_COLORS['high']}">High: {sev_counts['high']}</span>
    <span class="sev-pill" style="background:{SEVERITY_COLORS['medium']}">Medium: {sev_counts['medium']}</span>
    <span class="sev-pill" style="background:{SEVERITY_COLORS['low']}">Low: {sev_counts['low']}</span>
</div>

<h3>Category Breakdown</h3>
<table>
    <tr><th>Category</th><th>Count</th><th>Distribution</th></tr>
    {cat_rows}
</table>

<h3>Scenario Summary</h3>
<table>
    <tr><th>Scenario</th><th>Patterns</th><th>Steps</th><th>Duration</th><th>Status</th></tr>
    {scenario_rows}
</table>

<div class="compliance">
    <p>OECD Dark Pattern Compliance Score</p>
    <div class="compliance-score">{compliance_score}%</div>
    <p>{'Compliant' if compliance_score >= 70 else 'Needs Improvement' if compliance_score >= 40 else 'Non-Compliant'}</p>
</div>

<h3>Detailed Findings</h3>
{pattern_rows}

<div class="footer">
    <p>Generated by DarkShield -- AI-Powered Dark Pattern Detection | Nova Hackathon 2026</p>
    <p>Classification powered by Amazon Nova 2 Lite | Browser automation by Amazon Nova Act</p>
</div>

</body>
</html>"""

    return html

def generate_pdf(audit_data: dict) -> bytes:
    """Generate a PDF report from audit data using WeasyPrint."""
    try:
        from weasyprint import HTML
        html_content = generate_report_html(audit_data)
        pdf_bytes = HTML(string=html_content).write_pdf()
        logger.info("Generated PDF report: %d bytes", len(pdf_bytes))
        return pdf_bytes
    except ImportError:
        logger.error("WeasyPrint not installed. Install with: pip install weasyprint")
        raise
    except Exception:
        logger.exception("PDF generation failed")
        raise

def generate_html_file(audit_data: dict, output_path: str) -> str:
    """Generate an HTML report file (fallback if WeasyPrint unavailable)."""
    html = generate_report_html(audit_data)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
