"""Gera HTML de relatório a partir de Markdown (sem deps extras)."""

from __future__ import annotations

import html
import re
from pathlib import Path


SEVERITY_RE = re.compile(
    r"\b(Critical|High|Medium|Low|Info)\b",
    re.I,
)


def md_to_html_fragment(md: str) -> str:
    """Conversor Markdown → HTML suficiente para relatórios Hackteus."""
    if not md:
        return "<p class='empty'>(vazio)</p>"

    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    in_code = False
    code_buf: list[str] = []
    in_ul = False
    in_ol = False
    in_table = False
    table_rows: list[list[str]] = []

    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    def flush_table():
        nonlocal in_table, table_rows
        if not table_rows:
            return
        out.append('<div class="table-wrap"><table>')
        for i, row in enumerate(table_rows):
            tag = "th" if i == 0 else "td"
            # skip separator row |---|
            if i == 1 and all(re.fullmatch(r":?-+:?", c.strip()) for c in row):
                continue
            cells = "".join(f"<{tag}>{inline(c.strip())}</{tag}>" for c in row)
            out.append(f"<tr>{cells}</tr>")
        out.append("</table></div>")
        table_rows = []
        in_table = False

    def inline(text: str) -> str:
        text = html.escape(text)
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
        text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
        text = SEVERITY_RE.sub(_sev_span, text)
        return text

    def _sev_span(m: re.Match[str]) -> str:
        raw = m.group(1)
        cls = raw.lower()
        return f'<span class="sev sev-{cls}">{raw}</span>'

    for raw in lines:
        line = raw.rstrip()

        if line.startswith("```"):
            close_lists()
            flush_table()
            if in_code:
                out.append(
                    "<pre><code>"
                    + html.escape("\n".join(code_buf))
                    + "</code></pre>"
                )
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_buf.append(raw)
            continue

        if "|" in line and line.strip().startswith("|"):
            close_lists()
            cells = [c for c in line.strip().strip("|").split("|")]
            table_rows.append(cells)
            in_table = True
            continue
        if in_table:
            flush_table()

        if not line.strip():
            close_lists()
            continue

        if line.startswith("---") and set(line.strip()) <= {"-", " "}:
            close_lists()
            out.append("<hr />")
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            close_lists()
            level = len(m.group(1))
            out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
            continue

        m = re.match(r"^[-*]\s+(.*)$", line)
        if m:
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline(m.group(1))}</li>")
            continue

        m = re.match(r"^(\d+)\.\s+(.*)$", line)
        if m:
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{inline(m.group(2))}</li>")
            continue

        close_lists()
        out.append(f"<p>{inline(line)}</p>")

    close_lists()
    flush_table()
    if in_code:
        out.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")

    return "\n".join(out)


def build_document_html(
    *,
    title: str,
    markdown: str,
    scan_id: str = "",
    subtitle: str = "",
) -> str:
    body = md_to_html_fragment(markdown)
    sub = html.escape(subtitle) if subtitle else ""
    sid = html.escape(scan_id) if scan_id else ""
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{html.escape(title)}</title>
<style>
  :root {{
    --bg: #0c0c0c; --paper: #111; --ink: #d8d8d8; --muted: #888;
    --line: #333; --accent: #3b78ff; --critical: #ff5c6c; --high: #ff9f43;
    --medium: #f7c948; --low: #61d6d6; --info: #9aa0a6;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; font-family: "Cascadia Mono", Consolas, monospace;
    background: var(--bg); color: var(--ink); line-height: 1.55;
  }}
  .sheet {{
    max-width: 860px; margin: 2rem auto; padding: 2rem 2.2rem 3rem;
    background: var(--paper); border: 1px solid var(--line);
  }}
  header.doc-head {{
    border-bottom: 1px solid var(--line); padding-bottom: 1rem; margin-bottom: 1.5rem;
  }}
  header.doc-head .brand {{ color: var(--accent); letter-spacing: 0.12em; font-size: 0.75rem; }}
  header.doc-head h1 {{ margin: 0.4rem 0 0.2rem; font-size: 1.45rem; color: #fff; }}
  header.doc-head .meta {{ color: var(--muted); font-size: 0.8rem; }}
  h1,h2,h3,h4 {{ color: #fff; letter-spacing: 0.02em; }}
  h2 {{ font-size: 1.1rem; border-bottom: 1px solid var(--line); padding-bottom: 0.35rem; margin-top: 1.6rem; }}
  h3 {{ font-size: 1rem; color: #e8e8e8; }}
  p, li {{ font-size: 0.88rem; }}
  a {{ color: var(--accent); }}
  code {{ background: #000; padding: 0.1rem 0.35rem; border: 1px solid var(--line); font-size: 0.84em; }}
  pre {{ background: #000; border: 1px solid var(--line); padding: 0.85rem; overflow: auto; }}
  pre code {{ border: 0; padding: 0; background: transparent; }}
  hr {{ border: 0; border-top: 1px solid var(--line); margin: 1.4rem 0; }}
  .table-wrap {{ overflow: auto; margin: 0.8rem 0; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.82rem; }}
  th, td {{ border: 1px solid var(--line); padding: 0.45rem 0.55rem; text-align: left; }}
  th {{ background: #1a1a1a; color: #fff; }}
  .sev {{ display: inline-block; padding: 0.05rem 0.4rem; border: 1px solid; font-size: 0.75rem; letter-spacing: 0.04em; }}
  .sev-critical {{ color: var(--critical); border-color: var(--critical); }}
  .sev-high {{ color: var(--high); border-color: var(--high); }}
  .sev-medium {{ color: var(--medium); border-color: var(--medium); }}
  .sev-low {{ color: var(--low); border-color: var(--low); }}
  .sev-info {{ color: var(--info); border-color: var(--info); }}
  @media print {{
    body {{ background: #fff; color: #111; }}
    .sheet {{ border: 0; margin: 0; max-width: none; }}
    h1,h2,h3,h4 {{ color: #000; }}
  }}
</style>
</head>
<body>
  <article class="sheet">
    <header class="doc-head">
      <div class="brand">HACKTEUS REPORT</div>
      <h1>{html.escape(title)}</h1>
      <div class="meta">{sub}{" · " if sub and sid else ""}{f"scan {sid}" if sid else ""}</div>
    </header>
    <div class="doc-body">
{body}
    </div>
  </article>
</body>
</html>
"""


def write_report_docs(
    report_dir: Path,
    *,
    report_md: str | None,
    brief_md: str | None,
    scan_id: str,
    target_url: str = "",
) -> dict[str, str]:
    report_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    if brief_md:
        (report_dir / "BRIEF.md").write_text(brief_md, encoding="utf-8")
        html_brief = build_document_html(
            title="Brief de evidências",
            markdown=brief_md,
            scan_id=scan_id,
            subtitle=target_url,
        )
        p = report_dir / "BRIEF.html"
        p.write_text(html_brief, encoding="utf-8")
        paths["brief_html"] = str(p)
    if report_md:
        if not (report_dir / "REPORT.md").exists():
            (report_dir / "REPORT.md").write_text(report_md, encoding="utf-8")
        html_report = build_document_html(
            title="Relatório de segurança",
            markdown=report_md,
            scan_id=scan_id,
            subtitle=target_url,
        )
        p = report_dir / "REPORT.html"
        p.write_text(html_report, encoding="utf-8")
        paths["report_html"] = str(p)
    return paths
