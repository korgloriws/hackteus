from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
import json
import re
import uuid


class ScanMode(str, Enum):
    SURFACE = "surface"  # HTTP + browser (sem repo)
    SOURCE = "source"  # só repo
    HYBRID = "hybrid"  # surface + source quando houver Git


@dataclass
class Target:
    """Alvo com consentimento explícito (próprio ou contrato). Sem alvo padrão."""

    url: str
    name: str
    consent: str  # "owner" | "contract:<id>" | texto livre
    repo: Optional[str] = None
    mode: ScanMode = ScanMode.SURFACE

    def domain(self) -> str:
        m = re.match(r"https?://([^/]+)", self.url.strip())
        return (m.group(1) if m else self.name).lower()


@dataclass
class ScanContext:
    target: Target
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    root: Path = field(default_factory=lambda: Path("runs"))

    @property
    def evidence_dir(self) -> Path:
        return self.root / self.scan_id / "evidence"

    @property
    def report_dir(self) -> Path:
        return self.root / self.scan_id / "report"

    def ensure_dirs(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "target": asdict(self.target),
        }
        meta["target"]["mode"] = self.target.mode.value
        (self.root / self.scan_id / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
