"""CLI-like Cursor Agent: diálogo, stream, MCP, rules, local/cloud, plan/agent."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from hackteus.config import cursor_api_key
from hackteus import db as store
from hackteus.pipeline import DEFAULT_RUNS, _scan_dir
from hackteus.windows_sdk_patch import apply_windows_sdk_patches

ROOT = Path(__file__).resolve().parents[1]
CHAT_ROOT = DEFAULT_RUNS / "_cli"  # legado — só migração
DEFAULT_MODEL = "default"  # Auto
DEFAULT_RUNTIME = "local"
DEFAULT_MODE = "agent"
DEFAULT_SETTINGS = ["project", "user", "plugins"]


def normalize_model(model: str | None) -> str:
    m = (model or DEFAULT_MODEL).strip() or DEFAULT_MODEL
    if m.lower() in ("auto", "default"):
        return DEFAULT_MODEL
    return m


def normalize_runtime(runtime: str | None) -> str:
    r = (runtime or DEFAULT_RUNTIME).strip().lower()
    return "cloud" if r == "cloud" else "local"


def normalize_mode(mode: str | None) -> str:
    m = (mode or DEFAULT_MODE).strip().lower()
    return "plan" if m == "plan" else "agent"


def list_models() -> list[dict[str, Any]]:
    apply_windows_sdk_patches()
    api_key = cursor_api_key()
    if not api_key:
        return [{"id": DEFAULT_MODEL, "label": "auto", "description": ""}]

    from cursor_sdk import Cursor

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in Cursor.models.list(api_key=api_key):
        mid = getattr(m, "id", None) or ""
        if not mid or mid in seen:
            continue
        seen.add(mid)
        label = getattr(m, "display_name", None) or mid
        if mid == DEFAULT_MODEL:
            label = "auto"
        out.append(
            {
                "id": mid,
                "label": label,
                "description": getattr(m, "description", None) or "",
            }
        )

    if DEFAULT_MODEL not in seen:
        out.insert(0, {"id": DEFAULT_MODEL, "label": "auto", "description": ""})
    else:
        out.sort(key=lambda x: 0 if x["id"] == DEFAULT_MODEL else 1)
    return out


def list_cloud_repos() -> list[dict[str, str]]:
    apply_windows_sdk_patches()
    api_key = cursor_api_key()
    if not api_key:
        return []
    from cursor_sdk import Cursor

    out: list[dict[str, str]] = []
    try:
        for r in Cursor.repositories.list(api_key=api_key):
            url = getattr(r, "url", None) or ""
            if url:
                out.append({"url": url})
    except Exception:
        return []
    return out


def mcp_status() -> dict[str, Any]:
    """Status dos MCP file-based (project + user)."""
    project = ROOT / ".cursor" / "mcp.json"
    user = Path.home() / ".cursor" / "mcp.json"
    return {
        "project": _mcp_file_summary(project),
        "user": _mcp_file_summary(user),
        "setting_sources": DEFAULT_SETTINGS,
        "hint": "Edite .cursor/mcp.json (projeto) ou ~/.cursor/mcp.json (usuário).",
    }


def _mcp_file_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False, "servers": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"path": str(path), "exists": True, "servers": [], "error": str(exc)}
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    names = list(servers.keys()) if isinstance(servers, dict) else []
    return {"path": str(path), "exists": True, "servers": names}


def cli_capabilities() -> dict[str, Any]:
    return {
        "runtime": ["local", "cloud"],
        "mode": ["agent", "plan"],
        "default_model": DEFAULT_MODEL,
        "default_runtime": DEFAULT_RUNTIME,
        "default_mode": DEFAULT_MODE,
        "setting_sources": DEFAULT_SETTINGS,
        "streaming": True,
        "mcp": mcp_status(),
        "features": [
            "multi-turn",
            "models",
            "stream",
            "plan|agent",
            "local|cloud",
            "mcp (.cursor/mcp.json)",
            "rules/skills (setting_sources)",
            "scan-aware cwd",
        ],
        "not_in_sdk": [
            "Ask mode IDE",
            "Debug mode IDE",
            "Agents Window UI",
            "Bugbot PR product",
        ],
    }


def _session_path(session_id: str) -> Path:
    """Legado filesystem — usado só na migração/fallback."""
    CHAT_ROOT.mkdir(parents=True, exist_ok=True)
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_")[:64]
    if not safe:
        raise ValueError("session_id inválido")
    return CHAT_ROOT / f"{safe}.json"


def load_session(session_id: str) -> dict[str, Any] | None:
    store.ensure_db()
    data = store.load_chat_session(session_id)
    if data:
        return data
    # fallback JSON legado → importa
    path = _session_path(session_id)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    store.upsert_chat_session(data)
    return store.load_chat_session(session_id)


def save_session(data: dict[str, Any]) -> None:
    store.ensure_db()
    store.upsert_chat_session(data)


def list_sessions(*, limit: int = 50) -> list[dict[str, Any]]:
    store.ensure_db()
    items = store.list_chat_sessions(limit=limit)
    if items:
        return items
    # fallback legado → importa e lista do DB
    CHAT_ROOT.mkdir(parents=True, exist_ok=True)
    for path in CHAT_ROOT.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not data.get("session_id"):
            data["session_id"] = path.stem
        store.upsert_chat_session(data)
    return store.list_chat_sessions(limit=limit)


def delete_session(session_id: str) -> bool:
    store.ensure_db()
    deleted = store.delete_chat_session(session_id)
    path = _session_path(session_id)
    if path.exists():
        path.unlink()
        deleted = True
    return deleted


def update_session(
    session_id: str,
    *,
    label: str | None = None,
    notes: str | None = None,
) -> dict[str, Any] | None:
    store.ensure_db()
    # garante import se só existir no disco
    if not store.load_chat_session(session_id):
        load_session(session_id)
    return store.update_chat_session(session_id, label=label, notes=notes)


def resolve_cwd(scan_id: str | None) -> Path:
    if scan_id:
        d = _scan_dir(scan_id)
        if d:
            return d
    return ROOT


def send_chat(
    message: str,
    *,
    session_id: str | None = None,
    model: str | None = None,
    scan_id: str | None = None,
    reset: bool = False,
    runtime: str | None = None,
    mode: str | None = None,
    cloud_repo: str | None = None,
) -> dict[str, Any]:
    """One-shot (sem stream) — mantido para compat."""
    final: dict[str, Any] = {}
    for event in _collect_stream_sync(
        message,
        session_id=session_id,
        model=model,
        scan_id=scan_id,
        reset=reset,
        runtime=runtime,
        mode=mode,
        cloud_repo=cloud_repo,
    ):
        if event.get("type") == "done":
            final = event
        elif event.get("type") == "error":
            raise RuntimeError(event.get("text") or "diálogo falhou")
    if not final:
        raise RuntimeError("sem resposta do agent")
    return {
        "session_id": final["session_id"],
        "agent_id": final.get("agent_id"),
        "model": final.get("model"),
        "runtime": final.get("runtime"),
        "mode": final.get("mode"),
        "scan_id": final.get("scan_id"),
        "reply": final.get("reply") or "",
        "messages": final.get("messages") or [],
    }


def _collect_stream_sync(**kwargs: Any) -> list[dict[str, Any]]:
    return list(_sync_stream_iter(**kwargs))


def _sync_stream_iter(**kwargs: Any):
    apply_windows_sdk_patches()
    if sys.platform == "win32":
        async def _run():
            out = []
            async for ev in stream_chat(**kwargs):
                out.append(ev)
            return out

        for ev in asyncio.run(_run()):
            yield ev
    else:
        # sync path still uses async bridge for consistency
        async def _run():
            out = []
            async for ev in stream_chat(**kwargs):
                out.append(ev)
            return out

        for ev in asyncio.run(_run()):
            yield ev


async def stream_chat(
    message: str,
    *,
    session_id: str | None = None,
    model: str | None = None,
    scan_id: str | None = None,
    reset: bool = False,
    runtime: str | None = None,
    mode: str | None = None,
    cloud_repo: str | None = None,
) -> AsyncIterator[dict[str, Any]]:
    text = (message or "").strip()
    if not text:
        yield {"type": "error", "text": "Mensagem vazia."}
        return

    api_key = cursor_api_key()
    if not api_key:
        yield {
            "type": "error",
            "text": "CURSOR_API_KEY ausente. Coloque no arquivo .env na raiz do Hackteus.",
        }
        return

    model_id = normalize_model(model)
    runtime_id = normalize_runtime(runtime)
    mode_id = normalize_mode(mode)
    sid = session_id or uuid.uuid4().hex[:12]

    session = None if reset else load_session(sid)
    if session is None:
        session = {
            "session_id": sid,
            "agent_id": None,
            "model": model_id,
            "runtime": runtime_id,
            "mode": mode_id,
            "cloud_repo": (cloud_repo or "").strip() or None,
            "scan_id": scan_id,
            "cwd": str(resolve_cwd(scan_id)),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "messages": [],
        }
    else:
        changed = (
            session.get("model") != model_id
            or session.get("runtime") != runtime_id
            or (scan_id and session.get("scan_id") != scan_id)
            or (
                runtime_id == "cloud"
                and (cloud_repo or "").strip()
                and session.get("cloud_repo") != (cloud_repo or "").strip()
            )
        )
        if changed:
            session["agent_id"] = None
            session["model"] = model_id
            session["runtime"] = runtime_id
            session["mode"] = mode_id
            if cloud_repo is not None:
                session["cloud_repo"] = (cloud_repo or "").strip() or None
            if scan_id:
                session["scan_id"] = scan_id
                session["cwd"] = str(resolve_cwd(scan_id))
        else:
            session["mode"] = mode_id

    cwd = Path(session.get("cwd") or resolve_cwd(session.get("scan_id")))
    session["messages"].append(
        {
            "role": "user",
            "text": text,
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )
    # label automática na 1ª mensagem
    if not (session.get("label") or "").strip():
        session["label"] = text[:80]
    # persiste cedo (mesmo se o agent falhar depois)
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_session(session)

    prompt = text
    if not session.get("agent_id"):
        prompt = _bootstrap_prompt(
            text,
            scan_id=session.get("scan_id"),
            cwd=cwd,
            runtime=runtime_id,
            mode=mode_id,
        )

    yield {
        "type": "meta",
        "session_id": sid,
        "model": model_id,
        "runtime": runtime_id,
        "mode": mode_id,
        "scan_id": session.get("scan_id"),
        "cwd": str(cwd),
    }

    apply_windows_sdk_patches()
    reply_parts: list[str] = []
    agent_id = session.get("agent_id")

    try:
        async for ev in _run_turn_stream(
            prompt=prompt,
            cwd=cwd,
            api_key=api_key,
            model=model_id,
            agent_id=agent_id,
            runtime=runtime_id,
            mode=mode_id,
            cloud_repo=session.get("cloud_repo"),
        ):
            if ev["type"] == "text":
                reply_parts.append(ev.get("text") or "")
            if ev["type"] == "agent":
                agent_id = ev.get("agent_id") or agent_id
            yield ev
    except Exception as exc:
        # mantém o que já salvou (user msg)
        yield {"type": "error", "text": str(exc)}
        return

    reply = "".join(reply_parts).strip()
    session["agent_id"] = agent_id
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    session["messages"].append(
        {
            "role": "assistant",
            "text": reply,
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )
    save_session(session)

    yield {
        "type": "done",
        "session_id": sid,
        "agent_id": agent_id,
        "model": model_id,
        "runtime": runtime_id,
        "mode": mode_id,
        "scan_id": session.get("scan_id"),
        "reply": reply,
        "messages": session["messages"],
    }


def _bootstrap_prompt(
    user_text: str,
    *,
    scan_id: str | None,
    cwd: Path,
    runtime: str,
    mode: str,
) -> str:
    parts = [
        "Você é o assistente do Hackteus (análise defensiva autorizada).",
        "Responda em português, de forma direta. Não invente exploits nem passos de ataque.",
        f"Runtime: {runtime} · mode: {mode}",
        f"Workspace: {cwd}",
        "Respeite AGENTS.md e rules do projeto quando existirem.",
    ]
    if scan_id:
        parts.append(
            f"Há um scan aberto (`{scan_id}`). Evidências em `evidence/`, "
            "relatório em `report/REPORT.md`. Use-os quando o usuário perguntar."
        )
    if mode == "plan":
        parts.append(
            "Modo PLAN: foque em desenhar abordagem, riscos e checklist — "
            "não aplique mudanças destrutivas até o usuário pedir modo agent."
        )
    parts.append("")
    parts.append(user_text)
    return "\n".join(parts)


async def _run_turn_stream(
    *,
    prompt: str,
    cwd: Path,
    api_key: str,
    model: str,
    agent_id: str | None,
    runtime: str,
    mode: str,
    cloud_repo: str | None,
) -> AsyncIterator[dict[str, Any]]:
    from cursor_sdk import (
        AgentOptions,
        CloudAgentOptions,
        CloudRepository,
        LocalAgentOptions,
        SendOptions,
    )
    from cursor_sdk.asyncio import AsyncAgent, AsyncClient

    local = None
    cloud = None
    if runtime == "cloud":
        repos = []
        repo = (cloud_repo or "").strip()
        if repo:
            repos = [CloudRepository(url=repo)]
        cloud = CloudAgentOptions(repos=repos)
        # bridge workspace still needed for client; use project root
        bridge_cwd = str(ROOT)
    else:
        local = LocalAgentOptions(
            cwd=str(cwd),
            setting_sources=list(DEFAULT_SETTINGS),
        )
        bridge_cwd = str(cwd)

    options = AgentOptions(
        api_key=api_key,
        model=model,
        local=local,
        cloud=cloud,
        mode=mode,
    )

    async with await AsyncClient.launch_bridge(workspace=bridge_cwd) as client:
        if agent_id:
            agent = await AsyncAgent.resume(agent_id, options, client=client)
        else:
            agent = await AsyncAgent.create(options, client=client)

        yield {"type": "agent", "agent_id": agent.agent_id}

        try:
            run = await agent.send(prompt, SendOptions(mode=mode))
            async for message in run.stream():
                ev = _sdk_message_to_event(message)
                if ev:
                    yield ev
            result = await run.wait()
            status = getattr(result, "status", None) or getattr(run, "status", None)
            if status and status != "finished":
                yield {
                    "type": "status",
                    "text": f"run status: {status}",
                }
        finally:
            await agent.close()


def _sdk_message_to_event(message: Any) -> dict[str, Any] | None:
    mtype = getattr(message, "type", None) or ""
    if mtype == "assistant":
        text = _extract_assistant_text(message)
        if text:
            return {"type": "text", "text": text}
        return None
    if mtype == "thinking":
        text = getattr(message, "text", None) or ""
        if text:
            return {"type": "thinking", "text": text}
        return None
    if mtype == "tool_call":
        name = getattr(message, "name", None) or getattr(message, "tool", None) or "tool"
        status = getattr(message, "status", None) or ""
        return {"type": "tool", "name": str(name), "status": str(status)}
    if mtype == "tool_use":
        name = getattr(message, "name", None) or "tool"
        return {"type": "tool", "name": str(name), "status": "use"}
    if mtype == "task":
        text = getattr(message, "text", None) or ""
        status = getattr(message, "status", None) or ""
        return {"type": "task", "text": text, "status": str(status)}
    if mtype == "status":
        return {"type": "status", "text": str(getattr(message, "status", message))}
    # fallback: try text field
    text = getattr(message, "text", None)
    if isinstance(text, str) and text.strip() and mtype in ("", "assistant_message"):
        return {"type": "text", "text": text}
    return None


def _extract_assistant_text(message: Any) -> str:
    # SDKMessage assistant often has .message.content blocks
    inner = getattr(message, "message", None)
    if inner is not None:
        content = getattr(inner, "content", None)
        if content:
            parts = []
            for block in content:
                if getattr(block, "type", None) == "text":
                    parts.append(getattr(block, "text", "") or "")
                elif isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text") or "")
            return "".join(parts)
    return getattr(message, "text", None) or ""
