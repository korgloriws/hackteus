"""SQLite local — preserva análises (scans) e conversas do agente.

Evidências binárias continuam em `runs/<scan_id>/`; metadados, markdowns
editáveis e histórico de chat ficam no banco.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "hackteus.db"
DEFAULT_RUNS = ROOT / "runs"

_lock = threading.Lock()
_initialized = False


def db_path() -> Path:
    return DEFAULT_DB


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    p = path or DEFAULT_DB
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: Path | None = None, *, migrate: bool = True) -> Path:
    global _initialized
    p = path or DEFAULT_DB
    with _lock:
        with connect(p) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    started_at TEXT,
                    updated_at TEXT,
                    url TEXT,
                    name TEXT,
                    mode TEXT,
                    repo TEXT,
                    consent TEXT,
                    label TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    summary_json TEXT DEFAULT '{}',
                    meta_json TEXT DEFAULT '{}',
                    brief_md TEXT,
                    report_md TEXT,
                    has_report INTEGER DEFAULT 0,
                    model TEXT
                );

                CREATE TABLE IF NOT EXISTS chat_sessions (
                    session_id TEXT PRIMARY KEY,
                    label TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    model TEXT,
                    runtime TEXT,
                    mode TEXT,
                    scan_id TEXT,
                    agent_id TEXT,
                    cloud_repo TEXT,
                    cwd TEXT,
                    created_at TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    at TEXT,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_updated
                    ON scans(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_chat_updated
                    ON chat_sessions(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_chat_messages_session
                    ON chat_messages(session_id, id);
                """
            )
        if migrate:
            _initialized = True
            _migrate_from_filesystem(p)
        else:
            _initialized = True
    return p


def ensure_db() -> Path:
    if not _initialized or not DEFAULT_DB.exists():
        return init_db()
    return DEFAULT_DB


# ── scans ────────────────────────────────────────────────────────────────────


def upsert_scan(
    *,
    scan_id: str,
    started_at: str | None = None,
    updated_at: str | None = None,
    url: str | None = None,
    name: str | None = None,
    mode: str | None = None,
    repo: str | None = None,
    consent: str | None = None,
    label: str | None = None,
    notes: str | None = None,
    summary: dict[str, Any] | None = None,
    meta: dict[str, Any] | None = None,
    brief_md: str | None = None,
    report_md: str | None = None,
    model: str | None = None,
) -> None:
    ensure_db()
    now = _now()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            has_report = 1 if (report_md or "").strip() else 0
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, started_at, updated_at, url, name, mode, repo, consent,
                    label, notes, summary_json, meta_json, brief_md, report_md,
                    has_report, model
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    started_at or now,
                    updated_at or now,
                    url or "",
                    name or "",
                    mode or "",
                    repo,
                    consent or "",
                    label or name or "",
                    notes or "",
                    json.dumps(summary or {}, ensure_ascii=False),
                    json.dumps(meta or {}, ensure_ascii=False),
                    brief_md,
                    report_md,
                    has_report,
                    model,
                ),
            )
            return

        fields: dict[str, Any] = {"updated_at": updated_at or now}
        if started_at is not None:
            fields["started_at"] = started_at
        if url is not None:
            fields["url"] = url
        if name is not None:
            fields["name"] = name
        if mode is not None:
            fields["mode"] = mode
        if repo is not None:
            fields["repo"] = repo
        if consent is not None:
            fields["consent"] = consent
        if label is not None:
            fields["label"] = label
        if notes is not None:
            fields["notes"] = notes
        if summary is not None:
            fields["summary_json"] = json.dumps(summary, ensure_ascii=False)
        if meta is not None:
            fields["meta_json"] = json.dumps(meta, ensure_ascii=False)
        if brief_md is not None:
            fields["brief_md"] = brief_md
        if report_md is not None:
            fields["report_md"] = report_md
            fields["has_report"] = 1 if report_md.strip() else 0
        if model is not None:
            fields["model"] = model

        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(
            f"UPDATE scans SET {sets} WHERE scan_id = ?",
            (*fields.values(), scan_id),
        )


def get_scan_row(scan_id: str) -> dict[str, Any] | None:
    ensure_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    return _scan_row_to_dict(row)


def list_scan_rows(*, limit: int = 50) -> list[dict[str, Any]]:
    ensure_db()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT scan_id, started_at, updated_at, url, mode, label, notes, has_report
            FROM scans
            ORDER BY COALESCE(updated_at, started_at) DESC
            LIMIT ?
            """,
            (max(1, min(limit, 500)),),
        ).fetchall()
    return [
        {
            "scan_id": r["scan_id"],
            "started_at": r["started_at"],
            "updated_at": r["updated_at"],
            "url": r["url"],
            "mode": r["mode"],
            "label": r["label"] or r["scan_id"],
            "notes": r["notes"] or "",
            "has_report": bool(r["has_report"]),
        }
        for r in rows
    ]


def delete_scan_row(scan_id: str) -> bool:
    ensure_db()
    with connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        return cur.rowcount > 0


def _scan_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    meta = {}
    try:
        meta = json.loads(row["meta_json"] or "{}")
    except Exception:
        meta = {}
    if not meta:
        meta = {
            "scan_id": row["scan_id"],
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "label": row["label"],
            "notes": row["notes"],
            "target": {
                "url": row["url"],
                "name": row["name"],
                "mode": row["mode"],
                "repo": row["repo"],
                "consent": row["consent"],
            },
        }
    return {
        "scan_id": row["scan_id"],
        "meta": meta,
        "label": row["label"] or (meta.get("target") or {}).get("name") or row["scan_id"],
        "notes": row["notes"] or "",
        "brief_md": row["brief_md"],
        "report_md": row["report_md"],
        "started_at": row["started_at"],
        "updated_at": row["updated_at"],
        "url": row["url"],
        "mode": row["mode"],
        "has_report": bool(row["has_report"]),
        "model": row["model"],
        "summary": _safe_json(row["summary_json"]),
    }


# ── chat ─────────────────────────────────────────────────────────────────────


def upsert_chat_session(data: dict[str, Any]) -> None:
    ensure_db()
    sid = data["session_id"]
    now = _now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO chat_sessions (
                session_id, label, notes, model, runtime, mode, scan_id,
                agent_id, cloud_repo, cwd, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                label=excluded.label,
                notes=excluded.notes,
                model=excluded.model,
                runtime=excluded.runtime,
                mode=excluded.mode,
                scan_id=excluded.scan_id,
                agent_id=excluded.agent_id,
                cloud_repo=excluded.cloud_repo,
                cwd=excluded.cwd,
                updated_at=excluded.updated_at
            """,
            (
                sid,
                data.get("label") or "",
                data.get("notes") or "",
                data.get("model"),
                data.get("runtime"),
                data.get("mode"),
                data.get("scan_id"),
                data.get("agent_id"),
                data.get("cloud_repo"),
                data.get("cwd"),
                data.get("created_at") or now,
                data.get("updated_at") or now,
            ),
        )
        # replace messages when full payload provided
        if "messages" in data:
            conn.execute(
                "DELETE FROM chat_messages WHERE session_id = ?", (sid,)
            )
            for msg in data.get("messages") or []:
                conn.execute(
                    """
                    INSERT INTO chat_messages (session_id, role, text, at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        sid,
                        msg.get("role") or "user",
                        msg.get("text") or "",
                        msg.get("at") or now,
                    ),
                )


def load_chat_session(session_id: str) -> dict[str, Any] | None:
    ensure_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM chat_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None
        msgs = conn.execute(
            """
            SELECT role, text, at FROM chat_messages
            WHERE session_id = ?
            ORDER BY id ASC
            """,
            (session_id,),
        ).fetchall()
    return {
        "session_id": row["session_id"],
        "label": row["label"] or "",
        "notes": row["notes"] or "",
        "model": row["model"],
        "runtime": row["runtime"],
        "mode": row["mode"],
        "scan_id": row["scan_id"],
        "agent_id": row["agent_id"],
        "cloud_repo": row["cloud_repo"],
        "cwd": row["cwd"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "messages": [
            {"role": m["role"], "text": m["text"], "at": m["at"]} for m in msgs
        ],
    }


def list_chat_sessions(*, limit: int = 50) -> list[dict[str, Any]]:
    ensure_db()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT s.*,
                (SELECT COUNT(*) FROM chat_messages m WHERE m.session_id = s.session_id)
                    AS message_count,
                (SELECT text FROM chat_messages m
                    WHERE m.session_id = s.session_id AND m.role = 'user'
                    ORDER BY m.id DESC LIMIT 1) AS preview
            FROM chat_sessions s
            ORDER BY COALESCE(s.updated_at, s.created_at) DESC
            LIMIT ?
            """,
            (max(1, min(limit, 200)),),
        ).fetchall()
    out = []
    for r in rows:
        preview = (r["preview"] or "").strip()[:120]
        out.append(
            {
                "session_id": r["session_id"],
                "label": r["label"] or "",
                "notes": r["notes"] or "",
                "model": r["model"],
                "runtime": r["runtime"],
                "mode": r["mode"],
                "scan_id": r["scan_id"],
                "agent_id": r["agent_id"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"] or r["created_at"],
                "message_count": r["message_count"] or 0,
                "preview": preview,
            }
        )
    return out


def delete_chat_session(session_id: str) -> bool:
    ensure_db()
    with connect() as conn:
        cur = conn.execute(
            "DELETE FROM chat_sessions WHERE session_id = ?", (session_id,)
        )
        return cur.rowcount > 0


def update_chat_session(
    session_id: str,
    *,
    label: str | None = None,
    notes: str | None = None,
) -> dict[str, Any] | None:
    data = load_chat_session(session_id)
    if not data:
        return None
    if label is not None:
        data["label"] = label.strip()
    if notes is not None:
        data["notes"] = notes
    data["updated_at"] = _now()
    upsert_chat_session(data)
    return data


# ── migration ────────────────────────────────────────────────────────────────


def _migrate_from_filesystem(db: Path) -> None:
    runs = DEFAULT_RUNS
    if not runs.exists():
        return

    with connect(db) as conn:
        scan_count = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        chat_count = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_sessions"
        ).fetchone()["c"]

    if scan_count == 0:
        for path in runs.iterdir():
            if not path.is_dir() or path.name.startswith("_"):
                continue
            meta_path = path / "meta.json"
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            target = meta.get("target") or {}
            brief = _read(path / "report" / "BRIEF.md")
            report = _read(path / "report" / "REPORT.md")
            upsert_scan(
                scan_id=path.name,
                started_at=meta.get("started_at"),
                updated_at=meta.get("updated_at") or meta.get("started_at"),
                url=target.get("url") or "",
                name=target.get("name") or path.name,
                mode=target.get("mode") or "",
                repo=target.get("repo"),
                consent=target.get("consent") or "",
                label=meta.get("label") or target.get("name") or path.name,
                notes=meta.get("notes") or "",
                meta=meta,
                brief_md=brief,
                report_md=report,
            )

    if chat_count == 0:
        cli = runs / "_cli"
        if cli.exists():
            for path in cli.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not data.get("session_id"):
                    data["session_id"] = path.stem
                upsert_chat_session(data)


def _read(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    return None


def _safe_json(raw: str | None) -> dict[str, Any]:
    try:
        val = json.loads(raw or "{}")
        return val if isinstance(val, dict) else {}
    except Exception:
        return {}


def health_info() -> dict[str, Any]:
    ensure_db()
    with connect() as conn:
        scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        chats = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_sessions"
        ).fetchone()["c"]
        msgs = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages"
        ).fetchone()["c"]
    return {
        "ok": True,
        "path": str(DEFAULT_DB),
        "scans": scans,
        "chat_sessions": chats,
        "chat_messages": msgs,
    }
