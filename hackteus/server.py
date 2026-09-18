"""API + UI estática do Hackteus."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from hackteus.chat import (
    cli_capabilities,
    delete_session,
    list_cloud_repos,
    list_models,
    list_sessions,
    load_session,
    mcp_status,
    normalize_model,
    normalize_mode,
    normalize_runtime,
    send_chat,
    stream_chat,
    update_session,
)
from hackteus.collectors.browser import AuthCredentials
from hackteus.config import cursor_api_key, load_env
from hackteus import db as store
from hackteus.pipeline import (
    DEFAULT_RUNS,
    build_target,
    delete_scan,
    get_scan,
    list_scans,
    run_scan,
    update_scan,
)
from hackteus.report_html import write_report_docs

load_env()
store.ensure_db()

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"

app = FastAPI(title="Hackteus", version="0.1.0")


class ScanRequest(BaseModel):
    url: str
    name: str | None = None
    repo: str | None = None
    mode: str | None = Field(default=None, description="surface | source | hybrid")
    consent: str = "accepted"
    with_agent: bool = True
    with_browser: bool = True
    auth_user: str | None = None
    auth_email: str | None = None  # legado — alias de auth_user
    auth_password: str | None = None
    model: str = "default"  # auto


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    model: str | None = "default"
    scan_id: str | None = None
    reset: bool = False
    runtime: str | None = "local"  # local | cloud
    agent_mode: str | None = "agent"  # agent | plan
    cloud_repo: str | None = None


class ChatSessionUpdate(BaseModel):
    label: str | None = None
    notes: str | None = None


@app.get("/api/health")
def health():
    key = cursor_api_key()
    db_info = store.health_info()
    return {
        "ok": True,
        "cursor_api_key_configured": bool(key),
        "db": db_info,
    }


@app.get("/api/models")
def api_models():
    try:
        return {"models": list_models(), "default": "default"}
    except Exception as exc:
        raise HTTPException(502, f"falha ao listar modelos: {exc}") from exc


@app.get("/api/cli")
def api_cli_info():
    return cli_capabilities()


@app.get("/api/mcp")
def api_mcp():
    return mcp_status()


@app.get("/api/repos")
def api_repos():
    try:
        return {"repos": list_cloud_repos()}
    except Exception as exc:
        raise HTTPException(502, f"falha ao listar repos: {exc}") from exc


@app.get("/api/chat")
def api_list_chats():
    return {"sessions": list_sessions()}


@app.get("/api/chat/{session_id}")
def api_get_chat(session_id: str):
    data = load_session(session_id)
    if not data:
        raise HTTPException(404, "sessão não encontrada")
    return data


@app.put("/api/chat/{session_id}")
def api_update_chat(session_id: str, body: ChatSessionUpdate):
    data = update_session(session_id, label=body.label, notes=body.notes)
    if not data:
        raise HTTPException(404, "sessão não encontrada")
    return data


@app.delete("/api/chat/{session_id}")
def api_delete_chat(session_id: str):
    if not delete_session(session_id):
        raise HTTPException(404, "sessão não encontrada")
    return {"ok": True, "deleted": session_id}


@app.post("/api/chat")
def api_chat(body: ChatRequest):
    try:
        return send_chat(
            body.message,
            session_id=body.session_id,
            model=normalize_model(body.model),
            scan_id=body.scan_id,
            reset=body.reset,
            runtime=normalize_runtime(body.runtime),
            mode=normalize_mode(body.agent_mode),
            cloud_repo=body.cloud_repo,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"diálogo falhou: {exc}") from exc


@app.post("/api/chat/stream")
async def api_chat_stream(body: ChatRequest):
    import json

    async def event_gen():
        try:
            async for event in stream_chat(
                body.message,
                session_id=body.session_id,
                model=normalize_model(body.model),
                scan_id=body.scan_id,
                reset=body.reset,
                runtime=normalize_runtime(body.runtime),
                mode=normalize_mode(body.agent_mode),
                cloud_repo=body.cloud_repo,
            ):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'text': str(exc)}, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class ScanUpdateRequest(BaseModel):
    label: str | None = None
    notes: str | None = None
    report_md: str | None = None
    brief_md: str | None = None


@app.get("/api/scans")
def api_list_scans():
    return {"scans": list_scans()}


@app.get("/api/scans/{scan_id}")
def api_get_scan(scan_id: str):
    data = get_scan(scan_id)
    if not data:
        raise HTTPException(404, "scan não encontrado")
    return data


@app.put("/api/scans/{scan_id}")
def api_update_scan(scan_id: str, body: ScanUpdateRequest):
    data = update_scan(
        scan_id,
        label=body.label,
        notes=body.notes,
        report_md=body.report_md,
        brief_md=body.brief_md,
    )
    if not data:
        raise HTTPException(404, "scan não encontrado")
    return data


@app.delete("/api/scans/{scan_id}")
def api_delete_scan(scan_id: str):
    if not delete_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    return {"ok": True, "deleted": scan_id}


@app.get("/api/scans/{scan_id}/docs/{doc_name}")
def api_download_doc(scan_id: str, doc_name: str):
    """Baixa BRIEF/REPORT em .md ou .html."""
    allowed = {
        "brief.md": "BRIEF.md",
        "brief.html": "BRIEF.html",
        "report.md": "REPORT.md",
        "report.html": "REPORT.html",
    }
    key = doc_name.lower()
    if key not in allowed:
        raise HTTPException(404, "documento inválido")

    report_dir = DEFAULT_RUNS / scan_id / "report"
    path = report_dir / allowed[key]

    # gera HTML sob demanda se só existir MD
    if not path.exists() and key.endswith(".html"):
        md_name = "BRIEF.md" if key.startswith("brief") else "REPORT.md"
        md_path = report_dir / md_name
        if not md_path.exists() and key.startswith("brief"):
            # brief pode estar só no evidence combine — regenera via get_scan
            scan = get_scan(scan_id)
            if scan and scan.get("brief_md"):
                write_report_docs(
                    report_dir,
                    report_md=scan.get("report_md"),
                    brief_md=scan.get("brief_md"),
                    scan_id=scan_id,
                    target_url=(scan.get("meta") or {}).get("target", {}).get("url", ""),
                )
        elif md_path.exists():
            write_report_docs(
                report_dir,
                report_md=(report_dir / "REPORT.md").read_text(encoding="utf-8")
                if (report_dir / "REPORT.md").exists()
                else None,
                brief_md=md_path.read_text(encoding="utf-8")
                if md_name == "BRIEF.md"
                else None,
                scan_id=scan_id,
            )

    if not path.exists():
        raise HTTPException(404, "arquivo não encontrado")

    media = "text/html; charset=utf-8" if key.endswith(".html") else "text/markdown; charset=utf-8"
    return FileResponse(path, media_type=media, filename=allowed[key])


@app.post("/api/scan")
def api_scan(body: ScanRequest):
    if not (body.url or "").strip():
        raise HTTPException(400, "Informe a URL do alvo autorizado.")

    if body.with_agent and not cursor_api_key():
        raise HTTPException(
            400,
            "CURSOR_API_KEY ausente. Coloque no arquivo .env na raiz do Hackteus.",
        )

    # Permissão sempre aceita na UI; valor gravado só para auditoria do scan
    consent = (body.consent or "accepted").strip() or "accepted"

    username = (body.auth_user or body.auth_email or "").strip()
    password = body.auth_password or ""
    auth = None
    if username and password:
        auth = AuthCredentials(username=username, password=password)
    elif username or password:
        raise HTTPException(
            400,
            "Para autenticação informe usuário (ou email) e senha da conta de teste.",
        )

    try:
        target = build_target(
            url=body.url,
            name=body.name,
            repo=body.repo,
            mode=body.mode,
            consent=consent,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    result = run_scan(
        target,
        with_agent=body.with_agent,
        with_browser=body.with_browser,
        auth=auth,
        model=normalize_model(body.model),
    )
    if result.get("agent_error"):
        raise HTTPException(502, f"Análise falhou: {result['agent_error']}")
    return result


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/favicon.ico")
def favicon():
    icon = WEB / "static" / "favicon.svg"
    if icon.exists():
        return FileResponse(icon, media_type="image/svg+xml")
    raise HTTPException(404)


app.mount("/static", StaticFiles(directory=str(WEB / "static")), name="static")


def main():
    import uvicorn

    uvicorn.run(
        "hackteus.server:app",
        host="127.0.0.1",
        port=8787,
        reload=True,
    )


if __name__ == "__main__":
    main()
