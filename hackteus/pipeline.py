"""Pipeline de scan compartilhado (CLI + API)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from hackteus import db as store
from hackteus.collectors.browser import AuthCredentials, collect_browser
from hackteus.collectors.source import collect_source
from hackteus.collectors.surface import collect_http_surface
from hackteus.models import ScanContext, ScanMode, Target

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = ROOT / "runs"


def build_target(
    *,
    url: str,
    name: Optional[str] = None,
    repo: Optional[str] = None,
    mode: Optional[str] = None,
    consent: str = "accepted",
) -> Target:
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("URL do alvo é obrigatória.")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    resolved_mode = ScanMode(mode or ("hybrid" if repo else "surface"))
    host = cleaned.split("//", 1)[-1].split("/", 1)[0]
    return Target(
        url=cleaned,
        name=(name or host or "target").strip(),
        repo=repo.strip() if repo else None,
        consent=(consent or "").strip() or "accepted",
        mode=resolved_mode,
    )


def run_scan(
    target: Target,
    *,
    root: Path = DEFAULT_RUNS,
    with_agent: bool = False,
    with_browser: bool = True,
    auth: Optional[AuthCredentials] = None,
    model: str = "default",
) -> dict[str, Any]:
    store.ensure_db()
    ctx = ScanContext(target=target, root=root)
    ctx.ensure_dirs()

    store.upsert_scan(
        scan_id=ctx.scan_id,
        started_at=ctx.started_at,
        url=target.url,
        name=target.name,
        mode=target.mode.value,
        repo=target.repo,
        consent=target.consent,
        label=target.name,
        meta={
            "scan_id": ctx.scan_id,
            "started_at": ctx.started_at,
            "target": {**asdict(target), "mode": target.mode.value},
        },
        model=model,
    )

    results: dict[str, Any] = {}
    if target.mode in (ScanMode.SURFACE, ScanMode.HYBRID):
        results["surface"] = collect_http_surface(ctx)
        if with_browser:
            try:
                results["browser"] = collect_browser(ctx, auth=auth)
            except Exception as exc:  # noqa: BLE001
                results["browser"] = {"ok": False, "error": str(exc)}

    if target.mode in (ScanMode.SOURCE, ScanMode.HYBRID) and target.repo:
        results["source"] = collect_source(ctx)

    slim = {}
    for key, val in results.items():
        if not isinstance(val, dict):
            slim[key] = val
            continue
        slim[key] = {k: v for k, v in val.items() if k not in ("headers",)}

    (ctx.evidence_dir / "collect_results.json").write_text(
        json.dumps(slim, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    report_path = None
    agent_error = None
    if with_agent:
        try:
            from hackteus.agent_analyze import run_agent_analysis

            report_path = str(run_agent_analysis(ctx, model=model))
        except Exception as exc:  # noqa: BLE001
            agent_error = str(exc)

    combined_brief = _combine_briefs(ctx)
    report_md = _read_optional(ctx.report_dir / "REPORT.md")

    from hackteus.report_html import write_report_docs

    html_paths = write_report_docs(
        ctx.report_dir,
        report_md=report_md,
        brief_md=combined_brief or None,
        scan_id=ctx.scan_id,
        target_url=target.url,
    )

    if combined_brief:
        (ctx.report_dir / "BRIEF.md").write_text(combined_brief, encoding="utf-8")

    surface = results.get("surface") or {}
    browser = results.get("browser") or {}
    summary = {
        "secret_hits": len(surface.get("secret_hits") or []),
        "scripts": len(surface.get("scripts") or []),
        "source_maps": len(surface.get("source_maps") or []),
        "missing_security_headers": surface.get("missing_security_headers") or [],
        "source_ok": (results.get("source") or {}).get("ok"),
        "browser_ok": browser.get("ok", "error" not in browser),
        "browser_authenticated": browser.get("authenticated"),
        "api_endpoints": len(browser.get("api_endpoints") or []),
        "browser_findings": len(browser.get("findings") or []),
        "browser_error": browser.get("error"),
    }

    meta = {
        "scan_id": ctx.scan_id,
        "started_at": ctx.started_at,
        "target": {**asdict(target), "mode": target.mode.value},
        "label": target.name,
        "notes": "",
    }
    (ctx.root / ctx.scan_id / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    store.upsert_scan(
        scan_id=ctx.scan_id,
        started_at=ctx.started_at,
        url=target.url,
        name=target.name,
        mode=target.mode.value,
        repo=target.repo,
        consent=target.consent,
        label=target.name,
        summary=summary,
        meta=meta,
        brief_md=combined_brief or None,
        report_md=report_md,
        model=model,
    )

    return {
        "scan_id": ctx.scan_id,
        "target": {
            **asdict(target),
            "mode": target.mode.value,
        },
        "evidence_dir": str(ctx.evidence_dir),
        "report_dir": str(ctx.report_dir),
        "report_path": report_path,
        "brief_html_path": html_paths.get("brief_html"),
        "report_html_path": html_paths.get("report_html"),
        "agent_error": agent_error,
        "summary": summary,
        "brief_md": combined_brief,
        "report_md": report_md,
    }


def get_scan(scan_id: str, *, root: Path = DEFAULT_RUNS) -> dict[str, Any] | None:
    store.ensure_db()
    row = store.get_scan_row(scan_id)
    base = _scan_dir(scan_id, root=root)

    if row:
        brief = row.get("brief_md")
        report = row.get("report_md")
        if base:
            if brief is None:
                brief = _read_optional(
                    base / "report" / "BRIEF.md"
                ) or _combine_briefs_from_dir(base / "evidence")
            if report is None:
                report = _read_optional(base / "report" / "REPORT.md")
        return {
            "scan_id": scan_id,
            "meta": row.get("meta") or {},
            "label": row.get("label"),
            "notes": row.get("notes") or "",
            "brief_md": brief,
            "report_md": report,
            "evidence_dir": str(base / "evidence") if base else None,
            "report_dir": str(base / "report") if base else None,
        }

    if base is None:
        return None
    meta_path = base / "meta.json"
    if not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    brief = _read_optional(base / "report" / "BRIEF.md") or _combine_briefs_from_dir(
        base / "evidence"
    )
    report = _read_optional(base / "report" / "REPORT.md")
    target = meta.get("target") or {}
    store.upsert_scan(
        scan_id=scan_id,
        started_at=meta.get("started_at"),
        updated_at=meta.get("updated_at"),
        url=target.get("url") or "",
        name=target.get("name") or scan_id,
        mode=target.get("mode") or "",
        repo=target.get("repo"),
        consent=target.get("consent") or "",
        label=meta.get("label") or target.get("name") or scan_id,
        notes=meta.get("notes") or "",
        meta=meta,
        brief_md=brief,
        report_md=report,
    )
    return {
        "scan_id": scan_id,
        "meta": meta,
        "label": meta.get("label") or (meta.get("target") or {}).get("name"),
        "notes": meta.get("notes") or "",
        "brief_md": brief,
        "report_md": report,
        "evidence_dir": str(base / "evidence"),
        "report_dir": str(base / "report"),
    }


def list_scans(*, root: Path = DEFAULT_RUNS, limit: int = 50) -> list[dict[str, Any]]:
    store.ensure_db()
    items = store.list_scan_rows(limit=limit)
    if items:
        return items
    if not root.exists():
        return []
    legacy = []
    for path in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not path.is_dir() or path.name.startswith("_"):
            continue
        meta_path = path / "meta.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        target = meta.get("target") or {}
        legacy.append(
            {
                "scan_id": path.name,
                "started_at": meta.get("started_at"),
                "updated_at": meta.get("updated_at"),
                "url": target.get("url"),
                "mode": target.get("mode"),
                "label": meta.get("label") or target.get("name") or path.name,
                "notes": meta.get("notes") or "",
                "has_report": (path / "report" / "REPORT.md").exists(),
            }
        )
        if len(legacy) >= limit:
            break
    return legacy


def delete_scan(scan_id: str, *, root: Path = DEFAULT_RUNS) -> bool:
    import shutil

    store.ensure_db()
    base = _scan_dir(scan_id, root=root)
    deleted_fs = False
    if base is not None:
        shutil.rmtree(base)
        deleted_fs = True
    deleted_db = store.delete_scan_row(scan_id)
    return deleted_fs or deleted_db


def update_scan(
    scan_id: str,
    *,
    label: Optional[str] = None,
    notes: Optional[str] = None,
    report_md: Optional[str] = None,
    brief_md: Optional[str] = None,
    root: Path = DEFAULT_RUNS,
) -> dict[str, Any] | None:
    from datetime import datetime, timezone

    from hackteus.report_html import write_report_docs

    store.ensure_db()
    current = get_scan(scan_id, root=root)
    if current is None:
        return None

    base = _scan_dir(scan_id, root=root)
    meta = dict(current.get("meta") or {})
    if label is not None:
        meta["label"] = label.strip()
    if notes is not None:
        meta["notes"] = notes
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()

    current_report = current.get("report_md")
    current_brief = current.get("brief_md")

    if base is not None:
        meta_path = base / "meta.json"
        meta_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        report_dir = base / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        if report_md is not None:
            (report_dir / "REPORT.md").write_text(report_md, encoding="utf-8")
            current_report = report_md
        if brief_md is not None:
            (report_dir / "BRIEF.md").write_text(brief_md, encoding="utf-8")
            current_brief = brief_md
        write_report_docs(
            report_dir,
            report_md=current_report,
            brief_md=current_brief,
            scan_id=scan_id,
            target_url=(meta.get("target") or {}).get("url", ""),
        )
    else:
        if report_md is not None:
            current_report = report_md
        if brief_md is not None:
            current_brief = brief_md

    store.upsert_scan(
        scan_id=scan_id,
        label=meta.get("label"),
        notes=meta.get("notes"),
        meta=meta,
        brief_md=current_brief,
        report_md=current_report,
        updated_at=meta.get("updated_at"),
    )
    return get_scan(scan_id, root=root)


def _scan_dir(scan_id: str, *, root: Path = DEFAULT_RUNS) -> Path | None:
    """Resolve pasta do scan com validação anti path-traversal."""
    import re

    if not scan_id or not re.fullmatch(r"[a-zA-Z0-9_-]{4,64}", scan_id):
        return None
    base = (root / scan_id).resolve()
    try:
        base.relative_to(root.resolve())
    except ValueError:
        return None
    if not base.is_dir():
        return None
    return base


def _combine_briefs(ctx: ScanContext) -> str:
    return _combine_briefs_from_dir(ctx.evidence_dir)


def _combine_briefs_from_dir(evidence: Path) -> str:
    parts = []
    for rel in ("surface/BRIEF.md", "browser/BRIEF.md", "source/BRIEF.md"):
        text = _read_optional(evidence / rel)
        if text:
            parts.append(text.strip())
    return "\n\n---\n\n".join(parts) if parts else ""


def _read_optional(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    return None
