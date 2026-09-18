"""Collector de navegador — anon + sessão autenticada (conta de teste).

Equivalente a abrir o DevTools com permissão para “entrar no quintal”.
Credenciais NUNCA vão para o relatório em claro.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from hackteus.models import ScanContext

SENSITIVE_HEADER = re.compile(
    r"(authorization|cookie|set-cookie|x-api-key|x-auth)",
    re.I,
)
TOKENISH = re.compile(
    r"(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"
    r"|(Bearer\s+)(\S{8,})",
    re.I,
)


@dataclass
class AuthCredentials:
    """Usuário da conta de teste — pode ser email, login ou qualquer identificador."""

    username: str
    password: str
    login_path: str = "/login"
    login_api: str | None = None  # se None, tenta caminhos comuns


COMMON_LOGIN_APIS = (
    "/api/auth/login",
    "/api/login",
    "/api/session",
    "/api/sessions",
    "/auth/login",
    "/login",
    "/api/v1/auth/login",
    "/api/v1/login",
)


def _redact(text: str, limit: int = 4000) -> str:
    if not text:
        return ""

    def _sub(m: re.Match[str]) -> str:
        if m.group(1):
            return "eyJ…REDACTED"
        return f"{m.group(2)}***"

    out = TOKENISH.sub(_sub, text)
    if len(out) > limit:
        return out[:limit] + "…[truncated]"
    return out


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    clean = {}
    for k, v in headers.items():
        if SENSITIVE_HEADER.search(k):
            clean[k] = f"<redacted len={len(v)}>"
        else:
            clean[k] = v[:500]
    return clean


def collect_browser(
    ctx: ScanContext,
    *,
    auth: Optional[AuthCredentials] = None,
    headless: bool = True,
    extra_paths: Optional[list[str]] = None,
) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Instale Playwright: pip install playwright && playwright install chromium"
        ) from exc

    out_dir = ctx.evidence_dir / "browser"
    out_dir.mkdir(parents=True, exist_ok=True)

    base = ctx.target.url.rstrip("/")
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    paths = extra_paths or [
        "/",
        "/login",
        "/signin",
        "/sign-in",
        "/auth/login",
        "/dashboard",
        "/account",
        "/settings",
        "/admin",
        "/app",
    ]
    # unique preserve order
    seen: set[str] = set()
    nav_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            nav_paths.append(p)

    network: list[dict[str, Any]] = []
    console_errors: list[str] = []
    storage: dict[str, Any] = {}
    auth_result: dict[str, Any] = {"attempted": bool(auth), "ok": False}
    pages_ok: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []

    def on_request(req):
        pass

    def on_response(resp):
        try:
            req = resp.request
            url = resp.url
            # focar no mesmo host + APIs
            if urlparse(url).netloc != parsed.netloc and "/api" not in url:
                return
            entry = {
                "method": req.method,
                "url": url,
                "status": resp.status,
                "resource_type": req.resource_type,
                "request_headers": _redact_headers(dict(req.headers)),
                "response_headers": _redact_headers(dict(resp.headers)),
            }
            ctype = (resp.headers.get("content-type") or "").lower()
            if "json" in ctype or "/api" in url:
                try:
                    body = resp.text()
                    entry["body_preview"] = _redact(body, 2500)
                    if resp.status >= 500 and body:
                        findings.append(
                            {
                                "kind": "verbose_server_error",
                                "url": url,
                                "detail": _redact(body, 400),
                            }
                        )
                except Exception:
                    entry["body_preview"] = "<unreadable>"
            # cookie flags
            sc = resp.headers.get("set-cookie")
            if sc:
                flags = {
                    "has_httponly": "httponly" in sc.lower(),
                    "has_secure": "secure" in sc.lower(),
                    "has_samesite": "samesite" in sc.lower(),
                }
                entry["set_cookie_flags"] = flags
                if not flags["has_httponly"]:
                    findings.append(
                        {
                            "kind": "cookie_without_httponly",
                            "url": url,
                            "detail": "Set-Cookie sem HttpOnly",
                        }
                    )
            network.append(entry)
        except Exception:
            return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent="Hackteus/0.1 (+authorized-browser-scan)",
            ignore_https_errors=False,
            viewport={"width": 1280, "height": 720},
        )
        page = context.new_page()
        page.on("response", on_response)
        page.on(
            "console",
            lambda msg: console_errors.append(f"{msg.type}: {msg.text}")
            if msg.type == "error"
            else None,
        )

        # 1) anônimo — home
        page.goto(base, wait_until="networkidle", timeout=60000)
        pages_ok.append({"path": "/", "phase": "anon", "title": page.title()})

        # 2) login se credenciais
        if auth:
            auth_result.update(_try_login(page, origin, auth, findings))

        # 3) navegar rotas (pós-login se ok)
        phase = "auth" if auth_result.get("ok") else "anon"
        for path in nav_paths:
            if path == "/" and phase == "anon":
                continue
            url = urljoin(origin + "/", path.lstrip("/"))
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=45000)
                pages_ok.append(
                    {
                        "path": path,
                        "phase": phase,
                        "status": resp.status if resp else None,
                        "final_url": page.url,
                        "title": page.title(),
                    }
                )
                page.wait_for_timeout(800)
            except Exception as exc:
                pages_ok.append({"path": path, "phase": phase, "error": str(exc)[:300]})

        # storage (redacted)
        try:
            storage = page.evaluate(
                """() => ({
                  localStorage: Object.fromEntries(Object.keys(localStorage).map(k => [k, String(localStorage.getItem(k)||'').slice(0,80)])),
                  sessionStorageKeys: Object.keys(sessionStorage),
                  cookieLen: document.cookie.length
                })"""
            )
            if isinstance(storage.get("localStorage"), dict):
                ls = storage["localStorage"]
                for key in list(ls.keys()):
                    val = ls[key]
                    if key.lower() in ("token", "access_token", "jwt") or val.startswith("eyJ"):
                        ls[key] = f"<redacted jwt-like len={len(val)}>"
                        findings.append(
                            {
                                "kind": "jwt_in_localstorage",
                                "url": page.url,
                                "detail": f"chave `{key}` no localStorage (sessão roubável via XSS)",
                            }
                        )
        except Exception as exc:
            storage = {"error": str(exc)}

        # probes autenticados leves (só leitura)
        if auth_result.get("ok"):
            probes = _auth_probes(page, origin)
            auth_result["probes"] = probes
            for pr in probes:
                if pr.get("status") == 200 and pr.get("path") in (
                    "/api/auth/users",
                    "/api/auth/me",
                ):
                    pass
                if pr.get("status") == 200 and "users" in pr.get("path", ""):
                    findings.append(
                        {
                            "kind": "admin_or_user_list_reachable",
                            "url": pr["path"],
                            "detail": "Lista de usuários acessível com a sessão de teste",
                        }
                    )
                if pr.get("status") >= 500:
                    findings.append(
                        {
                            "kind": "probe_5xx",
                            "url": pr["path"],
                            "detail": _redact(str(pr.get("body_preview") or ""), 300),
                        }
                    )

        context.close()
        browser.close()

    # dedupe findings
    uniq = []
    seen_f = set()
    for f in findings:
        key = (f.get("kind"), f.get("url"), f.get("detail", "")[:80])
        if key in seen_f:
            continue
        seen_f.add(key)
        uniq.append(f)

    api_calls = [
        n
        for n in network
        if "/api" in n.get("url", "") or n.get("resource_type") == "fetch"
        or n.get("resource_type") == "xhr"
    ]

    summary: dict[str, Any] = {
        "origin": origin,
        "authenticated": bool(auth_result.get("ok")),
        "auth": {
            "attempted": auth_result.get("attempted"),
            "ok": auth_result.get("ok"),
            "method": auth_result.get("method"),
            "error": auth_result.get("error"),
            "username": auth.username if auth else None,
            "probes": auth_result.get("probes"),
        },
        "pages": pages_ok,
        "network_count": len(network),
        "api_calls_count": len(api_calls),
        "api_endpoints": sorted(
            {f"{n['method']} {urlparse(n['url']).path}" for n in api_calls}
        ),
        "console_errors": console_errors[:40],
        "storage": storage,
        "findings": uniq,
    }

    (out_dir / "network.json").write_text(
        json.dumps(network[:400], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_browser_brief(out_dir, summary)
    return summary


def _login_payloads(username: str, password: str) -> list[dict[str, str]]:
    """Varia payloads — sistemas usam email, username ou login."""
    u = username.strip()
    payloads: list[dict[str, str]] = []
    if "@" in u:
        payloads.append({"email": u, "password": password})
    payloads.append({"username": u, "password": password})
    payloads.append({"login": u, "password": password})
    payloads.append({"user": u, "password": password})
    # vários backends tipam o campo como email mesmo com login livre
    if "@" not in u:
        payloads.append({"email": u, "password": password})
    # dedupe
    seen: set[tuple[str, ...]] = set()
    out = []
    for p in payloads:
        key = tuple(sorted(p.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _try_login(page, origin: str, auth: AuthCredentials, findings: list) -> dict[str, Any]:
    """Prefer login via API (estável); fallback formulário /login."""
    result: dict[str, Any] = {"attempted": True, "ok": False}
    api_paths = (
        [auth.login_api]
        if auth.login_api
        else list(COMMON_LOGIN_APIS)
    )

    for api_path in api_paths:
        api_url = urljoin(origin + "/", str(api_path).lstrip("/"))
        for payload in _login_payloads(auth.username, auth.password):
            try:
                resp = page.request.post(api_url, json=payload)
                body = {}
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                token = (
                    body.get("token")
                    or body.get("access_token")
                    or body.get("accessToken")
                    or (body.get("data") or {}).get("token")
                )
                if resp.ok and token:
                    page.goto(origin, wait_until="domcontentloaded")
                    page.evaluate("(t) => localStorage.setItem('token', t)", token)
                    # também tenta sessionStorage / chaves comuns
                    page.evaluate(
                        """(t) => {
                          localStorage.setItem('access_token', t);
                          sessionStorage.setItem('token', t);
                        }""",
                        token,
                    )
                    page.reload(wait_until="networkidle")
                    result.update(
                        {
                            "ok": True,
                            "method": f"api:{api_path}:{','.join(k for k in payload if k != 'password')}",
                        }
                    )
                    me = page.request.get(
                        urljoin(origin + "/", "api/auth/me"),
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    result["me_status"] = me.status
                    if me.ok:
                        me_json = me.json()
                        user = me_json.get("user") or me_json
                        result["user"] = {
                            "email": user.get("email"),
                            "name": user.get("name") or user.get("username"),
                            "is_admin": user.get("is_admin"),
                            "id": user.get("id"),
                        }
                    return result
                result["api_status"] = resp.status
                result["api_error"] = _redact(str(body.get("error") or resp.text())[:200])
            except Exception as exc:
                result["api_exception"] = str(exc)[:200]

    # UI fallback
    try:
        login_url = urljoin(origin + "/", auth.login_path.lstrip("/"))
        page.goto(login_url, wait_until="domcontentloaded")
        user_sel = (
            'input[name="username"], input[name="login"], input[name="user"], '
            'input[autocomplete="username"], input[type="email"], input[name="email"], '
            'input[type="text"]'
        )
        page.locator(user_sel).first.fill(auth.username)
        page.fill('input[type="password"]', auth.password)
        page.click('button[type="submit"]')
        page.wait_for_timeout(2500)
        token = page.evaluate(
            """() => localStorage.getItem('token')
              || localStorage.getItem('access_token')
              || sessionStorage.getItem('token')"""
        )
        if token:
            result.update({"ok": True, "method": "ui_form"})
            return result
        result["error"] = result.get("api_error") or "login UI não gravou token"
    except Exception as exc:
        result["error"] = str(exc)[:300]

    findings.append(
        {
            "kind": "auth_login_failed",
            "url": auth.login_api or "/login",
            "detail": result.get("error") or result.get("api_error") or "falha no login",
        }
    )
    return result


def _auth_probes(page, origin: str) -> list[dict[str, Any]]:
    """GETs autenticados de leitura — caminhos comuns, sem mutação."""
    paths = [
        "/api/auth/me",
        "/api/me",
        "/api/user",
        "/api/users",
        "/api/profile",
        "/api/account",
        "/api/session",
        "/api/notifications",
        "/api/dashboard",
    ]
    out = []
    token = page.evaluate("() => localStorage.getItem('token')")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for path in paths:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            resp = page.request.get(url, headers=headers)
            preview = ""
            try:
                preview = _redact(resp.text(), 800)
            except Exception:
                preview = ""
            out.append(
                {
                    "path": path,
                    "status": resp.status,
                    "body_preview": preview,
                }
            )
        except Exception as exc:
            out.append({"path": path, "error": str(exc)[:200]})
    return out


def _write_browser_brief(out_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Browser brief (auto) — camada quintal",
        "",
        f"- Origin: `{summary.get('origin')}`",
        f"- Autenticado: **{summary.get('authenticated')}**",
        f"- Network entries: **{summary.get('network_count')}**",
        f"- API calls: **{summary.get('api_calls_count')}**",
        "",
    ]
    auth = summary.get("auth") or {}
    if auth.get("attempted"):
        lines += [
            "## Auth",
            "",
            f"- User: `{auth.get('username')}`",
            f"- OK: `{auth.get('ok')}` method=`{auth.get('method')}`",
            f"- Erro: `{auth.get('error') or auth.get('api_error') or '—'}`",
            "",
        ]
        user = auth.get("user")
        if user:
            lines.append(f"- Sessão: `{user}`")
            lines.append("")
    endpoints = summary.get("api_endpoints") or []
    if endpoints:
        lines += ["## Endpoints observados", ""]
        for e in endpoints[:80]:
            lines.append(f"- `{e}`")
        lines.append("")
    probes = auth.get("probes") or []
    if probes:
        lines += ["## Probes autenticados (GET)", ""]
        for p in probes:
            lines.append(
                f"- `{p.get('path')}` → **{p.get('status', p.get('error'))}**"
            )
        lines.append("")
    findings = summary.get("findings") or []
    if findings:
        lines += ["## Findings heurísticos", ""]
        for f in findings:
            lines.append(f"- **{f.get('kind')}**: {f.get('detail')} (`{f.get('url')}`)")
        lines.append("")
    storage = summary.get("storage") or {}
    if storage:
        lines += ["## Storage (redacted)", "", "```json", json.dumps(storage, indent=2, ensure_ascii=False)[:2000], "```", ""]
    (out_dir / "BRIEF.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
