"""Sobe a UI/API (usado por main.py e python -m hackteus)."""

from __future__ import annotations

import argparse
import os
import webbrowser
from threading import Timer

from hackteus.config import cursor_api_key, load_env


def run_ui(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    open_browser: bool = True,
    reload: bool = False,
) -> None:
    load_env()
    url = f"http://{host}:{port}"
    key_ok = bool(cursor_api_key())

    print("Hackteus")
    print(f"  UI     -> {url}")
    print(f"  .env   -> CURSOR_API_KEY {'ok' if key_ok else 'AUSENTE (edite .env)'}")
    if open_browser:
        Timer(1.2, lambda: webbrowser.open(url)).start()

    import uvicorn

    uvicorn.run(
        "hackteus.server:app",
        host=host,
        port=port,
        reload=reload,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Hackteus — cerca elétrica")
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8787")),
    )
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)
    run_ui(
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
        reload=args.reload,
    )
