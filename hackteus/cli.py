"""CLI Hackteus — scan autorizado (próprio ou com contrato)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from hackteus.collectors.browser import AuthCredentials
from hackteus.config import load_env
from hackteus.pipeline import DEFAULT_RUNS, build_target, run_scan

load_env()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hackteus",
        description="Cerca elétrica: scan de superfície/browser/source com consentimento.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Rodar collectors (+ agente opcional)")
    scan.add_argument("--url", required=True, help="URL do alvo autorizado")
    scan.add_argument("--name", default=None)
    scan.add_argument("--repo", default=None, help="Git URL se liberado")
    scan.add_argument(
        "--mode",
        choices=["surface", "source", "hybrid"],
        default=None,
        help="Default: surface, ou hybrid se --repo",
    )
    scan.add_argument(
        "--consent",
        default="owner",
        help="Ex: owner | contract:ACME-2026-01",
    )
    scan.add_argument("--root", type=Path, default=DEFAULT_RUNS)
    scan.add_argument(
        "--agent",
        action="store_true",
        help="Após coletar, rodar Cursor Agent (precisa CURSOR_API_KEY)",
    )
    scan.add_argument(
        "--no-browser",
        action="store_true",
        help="Pula Playwright",
    )
    scan.add_argument(
        "--auth-user",
        default=None,
        help="Usuário da conta de teste (email, login ou qualquer id)",
    )
    scan.add_argument("--auth-email", default=None, help="Alias legado de --auth-user")
    scan.add_argument("--auth-password", default=None)

    ui = sub.add_parser("ui", help="Sobe a interface web em http://127.0.0.1:8787")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8787)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "ui":
        import uvicorn

        uvicorn.run(
            "hackteus.server:app",
            host=args.host,
            port=args.port,
            reload=True,
        )
        return 0

    if args.cmd != "scan":
        return 1

    try:
        target = build_target(
            url=args.url,
            name=args.name,
            repo=args.repo,
            mode=args.mode,
            consent=args.consent,
        )
    except ValueError as exc:
        print(f"[hackteus] {exc}", file=sys.stderr)
        return 1

    username = (
        args.auth_user
        or args.auth_email
        or os.environ.get("HACKTEUS_AUTH_USER")
        or os.environ.get("HACKTEUS_AUTH_EMAIL")
    )
    password = args.auth_password or os.environ.get("HACKTEUS_AUTH_PASSWORD")
    auth = None
    if username and password:
        auth = AuthCredentials(username=username, password=password)

    print(
        f"[hackteus] mode={target.mode.value} url={target.url} "
        f"browser={not args.no_browser} auth={bool(auth)} agent={args.agent}"
    )
    result = run_scan(
        target,
        root=args.root,
        with_agent=args.agent,
        with_browser=not args.no_browser,
        auth=auth,
    )
    print(f"[hackteus] scan_id={result['scan_id']}")
    print(f"[hackteus] evidence={result['evidence_dir']}")
    s = result.get("summary") or {}
    if s.get("browser_error"):
        print(f"[hackteus] browser error: {s['browser_error']}", file=sys.stderr)
    if result.get("agent_error"):
        print(f"[hackteus] agent error: {result['agent_error']}", file=sys.stderr)
        return 2
    if result.get("report_path"):
        print(f"[hackteus] report → {result['report_path']}")
    elif not args.agent:
        print("           rode com --agent ou abra a UI para análise LLM")
    return 0


if __name__ == "__main__":
    sys.exit(main())
