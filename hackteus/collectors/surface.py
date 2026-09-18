"""Collector de superfície pública — automatiza o que o DevTools já mostra."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from hackteus.models import ScanContext

USER_AGENT = "Hackteus/0.1 (+authorized-security-scan; contact=owner)"

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "api_key_literal"),
    (r"(?i)(secret|token|password|passwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "secret_literal"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"(?i)sk_live_[a-zA-Z0-9]{20,}", "stripe_live_key"),
    (r"(?i)AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "private_key_pem"),
    (r"(?i)mongodb(\+srv)?://[^\s'\"\\]+", "mongodb_uri"),
    (r"(?i)postgres(ql)?://[^\s'\"\\]+", "postgres_uri"),
]


def _safe_name(url: str) -> str:
    p = urlparse(url)
    path = (p.path or "/").strip("/").replace("/", "_") or "index"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", f"{p.netloc}_{path}")[:180]


def collect_http_surface(ctx: ScanContext) -> dict[str, Any]:
    """Fetch HTML, headers, linked scripts; heuristic secret scan; try source maps."""
    out_dir = ctx.evidence_dir / "surface"
    out_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir = out_dir / "scripts"
    scripts_dir.mkdir(exist_ok=True)

    summary: dict[str, Any] = {
        "url": ctx.target.url,
        "headers": {},
        "cookies": [],
        "scripts": [],
        "source_maps": [],
        "secret_hits": [],
        "security_headers": {},
    }

    with httpx.Client(
        follow_redirects=True,
        timeout=30.0,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        resp = client.get(ctx.target.url)
        html_path = out_dir / "index.html"
        html_path.write_text(resp.text, encoding="utf-8", errors="replace")

        summary["final_url"] = str(resp.url)
        summary["status_code"] = resp.status_code
        summary["headers"] = dict(resp.headers)
        summary["cookies"] = [
            {"name": c.name, "value_len": len(c.value), "domain": c.domain}
            for c in resp.cookies.jar
        ]

        interesting = [
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "access-control-allow-origin",
            "set-cookie",
            "server",
            "x-powered-by",
        ]
        lower = {k.lower(): v for k, v in resp.headers.items()}
        summary["security_headers"] = {
            h: lower.get(h, None) for h in interesting
        }
        summary["missing_security_headers"] = [
            h
            for h in interesting
            if h
            not in (
                "server",
                "x-powered-by",
                "set-cookie",
                "access-control-allow-origin",
            )
            and lower.get(h) is None
        ]

        script_urls = re.findall(
            r"""<script[^>]+src=["']([^"']+)["']""",
            resp.text,
            flags=re.I,
        )
        inline_scripts = re.findall(
            r"<script(?![^>]+src=)[^>]*>(.*?)</script>",
            resp.text,
            flags=re.I | re.S,
        )
        if inline_scripts:
            inline_path = scripts_dir / "_inline.js"
            inline_path.write_text("\n\n".join(inline_scripts), encoding="utf-8")
            summary["scripts"].append({"url": "(inline)", "path": str(inline_path)})
            summary["secret_hits"].extend(
                _scan_secrets("(inline)", "\n\n".join(inline_scripts))
            )

        for src in script_urls:
            abs_url = urljoin(str(resp.url), src)
            entry: dict[str, Any] = {"url": abs_url}
            try:
                sresp = client.get(abs_url)
                fname = _safe_name(abs_url) + ".js"
                fpath = scripts_dir / fname
                fpath.write_bytes(sresp.content)
                entry["path"] = str(fpath)
                entry["status_code"] = sresp.status_code
                entry["bytes"] = len(sresp.content)
                text = sresp.text
                summary["secret_hits"].extend(_scan_secrets(abs_url, text))

                map_url = None
                # sourceMappingURL comment
                m = re.search(
                    r"sourceMappingURL\s*=\s*(\S+)",
                    text[-2000:] if len(text) > 2000 else text,
                )
                if m:
                    map_url = urljoin(abs_url, m.group(1).strip())
                else:
                    # conventional guess
                    map_url = abs_url + ".map"

                if map_url:
                    try:
                        mresp = client.get(map_url)
                        if mresp.status_code == 200 and mresp.content[:1] == b"{":
                            mpath = scripts_dir / (fname + ".map")
                            mpath.write_bytes(mresp.content)
                            summary["source_maps"].append(
                                {"url": map_url, "path": str(mpath)}
                            )
                            summary["secret_hits"].extend(
                                _scan_secrets(map_url, mresp.text)
                            )
                            entry["source_map"] = map_url
                    except httpx.HTTPError:
                        pass
            except httpx.HTTPError as exc:
                entry["error"] = str(exc)
            summary["scripts"].append(entry)

    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_surface_brief(out_dir, summary)
    return summary


def _scan_secrets(source: str, text: str) -> list[dict[str, str]]:
    hits = []
    for pattern, kind in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            raw = m.group(0)
            redacted = raw[:6] + "…" + raw[-4:] if len(raw) > 12 else "***"
            hits.append(
                {
                    "kind": kind,
                    "source": source,
                    "redacted": redacted,
                    "span": f"{m.start()}:{m.end()}",
                }
            )
    return hits


def _write_surface_brief(out_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Surface brief (auto)",
        "",
        f"- URL: `{summary.get('final_url', summary.get('url'))}`",
        f"- Status: `{summary.get('status_code')}`",
        f"- Scripts: **{len(summary.get('scripts', []))}**",
        f"- Source maps: **{len(summary.get('source_maps', []))}**",
        f"- Secret heuristic hits: **{len(summary.get('secret_hits', []))}**",
        "",
        "## Security headers",
        "",
    ]
    for k, v in (summary.get("security_headers") or {}).items():
        lines.append(f"- `{k}`: `{v}`")
    missing = summary.get("missing_security_headers") or []
    if missing:
        lines += ["", "## Missing headers", ""]
        for h in missing:
            lines.append(f"- `{h}`")
    hits = summary.get("secret_hits") or []
    if hits:
        lines += ["", "## Possible secrets (redacted)", ""]
        for h in hits[:50]:
            lines.append(
                f"- **{h['kind']}** in `{h['source']}` → `{h['redacted']}`"
            )
    (out_dir / "BRIEF.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
