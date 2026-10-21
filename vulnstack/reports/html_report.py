"""Self-contained HTML report rendering.

Produces a single HTML file with inline CSS and no remote resources or
JavaScript. All untrusted text (website-derived evidence, CVE descriptions,
header values) is HTML-escaped before insertion to prevent injection. The
report is explicit that structured version matches indicate a potentially
affected component, not proof of exploitability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from vulnstack.cve.search import Classification
from vulnstack.scanner import ScanResult

_SEVERITY_COLORS = {
    "CRITICAL": "#7b1111",
    "HIGH": "#b23b00",
    "MEDIUM": "#8a6d00",
    "LOW": "#2d6a2d",
    "NONE": "#444",
    "UNKNOWN": "#555",
}

_CLASS_LABELS = {
    Classification.MATCHED_AFFECTED_RANGE.value: "Version matches an affected range",
    Classification.VERSION_UNKNOWN.value: "Potentially relevant — version unknown (verify)",
    Classification.PRODUCT_MAPPING_AMBIGUOUS.value: "Product mapping ambiguous (verify)",
    Classification.AFFECTED_RANGE_UNAVAILABLE.value: "No affected-range data (verify)",
    Classification.SOURCE_DATA_INCOMPLETE.value: "Source data incomplete (verify)",
    Classification.VERSION_NOT_MATCHED.value: "Detected version not in affected range",
}


def _e(value) -> str:
    return escape("" if value is None else str(value))


def render(result: ScanResult) -> str:
    data = result.to_dict()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    tech_rows = []
    for t in result.technologies:
        tech_rows.append(
            "<tr>"
            f"<td>{_e(t.name)}</td>"
            f"<td>{_e(t.category)}</td>"
            f"<td>{_e(t.version or '—')}</td>"
            f"<td>{_e(t.confidence)}</td>"
            f"<td>{_e('; '.join(t.evidence[:4]))}</td>"
            "</tr>"
        )

    severity_counts: dict[str, int] = {}
    for f in result.findings:
        key = (f.severity or "UNKNOWN").upper()
        severity_counts[key] = severity_counts.get(key, 0) + 1
    sev_items = "".join(
        f'<span class="sev" style="background:{_SEVERITY_COLORS.get(k, "#555")}">'
        f"{_e(k)}: {v}</span>"
        for k, v in sorted(severity_counts.items())
    )

    finding_blocks = []
    for f in result.findings:
        sev = (f.severity or "UNKNOWN").upper()
        color = _SEVERITY_COLORS.get(sev, "#555")
        products = "".join(
            "<li>"
            f"{_e(mp.technology)} "
            f"(detected: {_e(mp.detected_version or 'unknown')}) → "
            f"{_e(mp.cpe_vendor)}:{_e(mp.cpe_product)} — "
            f"<em>{_e(mp.classification.value)}</em>: {_e(mp.detail)}"
            "</li>"
            for mp in f.matched_products
        )
        refs = "".join(
            f'<li><a href="{_e(r.get("url"))}" rel="noopener noreferrer nofollow">'
            f'{_e(r.get("url"))}</a></li>'
            for r in f.references[:12]
        )
        finding_blocks.append(
            f"""
            <div class="finding">
              <h3><span class="sev" style="background:{color}">{_e(sev)}</span>
                  {_e(f.cve_id)}
                  <span class="score">CVSS {_e(f.cvss_score if f.cvss_score is not None else 'n/a')}
                  ({_e(f.cvss_version or 'n/a')})</span></h3>
              <p class="classification">{_e(_CLASS_LABELS.get(f.classification.value, f.classification.value))}</p>
              <p class="desc">{_e(f.description)}</p>
              <p class="meta">Published: {_e(f.published or 'n/a')} · Source: {_e(f.source)}</p>
              <p class="meta">Matched products:</p>
              <ul class="products">{products}</ul>
              {f'<p class="meta">References:</p><ul class="refs">{refs}</ul>' if refs else ''}
            </div>
            """
        )

    warnings = "".join(f"<li>{_e(w)}</li>" for w in result.warnings)
    errors = "".join(f"<li>{_e(e)}</li>" for e in result.errors)
    unresolved = "".join(
        f"<li>{_e(u)}</li>" for u in (result.search_report.unresolved if result.search_report else [])
    )

    db = data.get("database") or {}
    summary = data["summary"]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnStack report — {_e(result.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#f6f7f9; color:#1b1b1b; }}
  header {{ background:#13233b; color:#fff; padding:1.2rem 1.6rem; }}
  header h1 {{ margin:0; font-size:1.3rem; }}
  header .sub {{ opacity:.8; font-size:.9rem; margin-top:.2rem; word-break:break-all; }}
  main {{ max-width: 1000px; margin: 0 auto; padding: 1rem 1.2rem 3rem; }}
  section {{ background:#fff; border:1px solid #e1e4e8; border-radius:8px; padding:1rem 1.2rem; margin:1rem 0; }}
  h2 {{ font-size:1.05rem; border-bottom:1px solid #e1e4e8; padding-bottom:.4rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.86rem; }}
  th, td {{ text-align:left; padding:.4rem .5rem; border-bottom:1px solid #eee; vertical-align:top; }}
  th {{ background:#f0f2f5; }}
  .sev {{ color:#fff; padding:.1rem .5rem; border-radius:4px; font-size:.72rem; font-weight:700; margin-right:.3rem; }}
  .score {{ font-size:.8rem; color:#555; font-weight:400; margin-left:.4rem; }}
  .finding {{ border:1px solid #e1e4e8; border-radius:6px; padding:.6rem .9rem; margin:.7rem 0; }}
  .finding h3 {{ margin:.1rem 0 .3rem; font-size:1rem; }}
  .classification {{ font-weight:600; margin:.2rem 0; }}
  .desc {{ font-size:.88rem; }}
  .meta {{ font-size:.8rem; color:#555; margin:.2rem 0; }}
  ul {{ margin:.2rem 0 .6rem 1.1rem; font-size:.82rem; }}
  .note {{ background:#fff7e6; border:1px solid #ffe0a3; padding:.6rem .9rem; border-radius:6px; font-size:.85rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#15181d; color:#e6e6e6; }}
    section, .finding {{ background:#1d2127; border-color:#2a2f37; }}
    th {{ background:#242933; }}
    th, td {{ border-color:#2a2f37; }}
    .note {{ background:#2a2410; border-color:#5a4a16; color:#f0e4c0; }}
    .meta, .score {{ color:#9aa4b2; }}
    a {{ color:#6ea8fe; }}
  }}
</style>
</head>
<body>
<header>
  <h1>VulnStack vulnerability report</h1>
  <div class="sub">Target: {_e(result.target)} · Final URL: {_e(result.final_url or 'n/a')}</div>
  <div class="sub">Scan time: {_e(result.timestamp)} · Generated: {_e(generated)} · Tool v{_e(result.tool_version)}</div>
</header>
<main>
  <section>
    <h2>Summary</h2>
    <p>Status: <strong>{_e(result.status)}</strong> ·
       Technologies detected: <strong>{summary['technologies_detected']}</strong> ·
       Findings: <strong>{summary['findings_total']}</strong></p>
    <p>{sev_items or '<em>No CVE findings.</em>'}</p>
    <p class="note">A structured version match indicates a <strong>potentially affected component</strong>,
       not proof that the component is reachable or exploitable. Verify findings before acting.</p>
  </section>

  <section>
    <h2>Technology inventory</h2>
    <table>
      <tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr>
      {''.join(tech_rows) or '<tr><td colspan="5"><em>No technologies detected.</em></td></tr>'}
    </table>
    {f'<p class="meta">No local product mapping for: {", ".join(_e(u) for u in (result.search_report.unresolved if result.search_report else []))}</p>' if (result.search_report and result.search_report.unresolved) else ''}
  </section>

  <section>
    <h2>Vulnerability findings</h2>
    {''.join(finding_blocks) or '<p><em>No candidate CVEs found in the local database.</em></p>'}
  </section>

  <section>
    <h2>Database &amp; data source</h2>
    <p class="meta">Initialized: {_e(db.get('initialized'))} ·
       Total CVEs: {_e(db.get('total_cves'))} ·
       Last successful sync: {_e(db.get('last_successful_sync') or 'never')}
       {' · <strong>possibly outdated</strong>' if db.get('stale') else ''}</p>
    <p class="meta">Database path: {_e(db.get('path'))}</p>
  </section>

  {f'<section><h2>Warnings</h2><ul>{warnings}</ul></section>' if warnings else ''}
  {f'<section><h2>Errors</h2><ul>{errors}</ul></section>' if errors else ''}
</main>
</body>
</html>
"""
