"""Clone opcional do repositório quando o cliente (ou você) libera o source."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from hackteus.models import ScanContext


def collect_source(ctx: ScanContext) -> dict[str, Any]:
    if not ctx.target.repo:
        return {"skipped": True, "reason": "no repo on target"}

    src_dir = ctx.evidence_dir / "source"
    src_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = src_dir / "repo"

    result: dict[str, Any] = {"repo": ctx.target.repo, "path": str(repo_dir)}

    if repo_dir.exists() and (repo_dir / ".git").exists():
        pull = subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only"],
            capture_output=True,
            text=True,
        )
        result["action"] = "pull"
        result["ok"] = pull.returncode == 0
        result["stderr"] = pull.stderr[-2000:]
    else:
        clone = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                ctx.target.repo,
                str(repo_dir),
            ],
            capture_output=True,
            text=True,
        )
        result["action"] = "clone"
        result["ok"] = clone.returncode == 0
        result["stderr"] = clone.stderr[-2000:]

    (src_dir / "summary.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    brief = [
        "# Source brief (auto)",
        "",
        f"- Repo: `{ctx.target.repo}`",
        f"- Action: `{result.get('action')}`",
        f"- OK: `{result.get('ok')}`",
        f"- Path: `{repo_dir}`",
        "",
        "O agente deve analisar este tree em busca de secrets, auth fraca e misconfig.",
        "",
    ]
    (src_dir / "BRIEF.md").write_text("\n".join(brief), encoding="utf-8")
    return result
