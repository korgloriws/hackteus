"""Análise das evidências via Cursor Agent (cursor-sdk).

No Windows nativo usamos a API **async** (a sync quebra em pipes/selectors).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from hackteus.config import cursor_api_key
from hackteus.models import ScanContext
from hackteus.windows_sdk_patch import apply_windows_sdk_patches

ANALYSIS_PROMPT = """Você é o analista de segurança do Hackteus (modo defensivo / autorizado).

Contexto:
- Alvo com consentimento: {consent}
- URL: {url}
- Modo: {mode}

Pasta de trabalho contém evidências em `evidence/`:
- `evidence/surface/` — HTTP estático (HTML, JS, headers, source maps, secrets heurísticos)
- `evidence/browser/` — Playwright: network, endpoints /api, storage, login de conta de teste (tokens SEMPRE redacted)
- `evidence/source/` — só se existir (repo liberado)

Prioridade de leitura nesta ordem:
1) evidence/browser/BRIEF.md (camada “quintal” — a mais comum em clientes sem Git)
2) evidence/surface/BRIEF.md
3) evidence/source/ só se existir; se NÃO existir, NÃO invente achados de código-fonte

Tarefa:
1. Liste achados priorizados (Critical / High / Medium / Low / Info) com base NAS EVIDÊNCIAS.
2. Para cada achado: evidência (arquivo/caminho), impacto, remediação concreta.
3. Não invente exploits nem passos de exploração. Foque em exposição e endurecimento.
4. Se autenticado: analise probes GET, JWT em localStorage, cookies sem flags, erros 5xx verbosos, APIs acessíveis à sessão.
5. Escreva o relatório final em `report/REPORT.md` com estrutura clara:
   - Título e metadados (alvo, modo, data)
   - Resumo executivo (curto)
   - Achados por severidade com subtítulos `#### C-01 — …` / `#### H-01 — …`
   - Em cada achado use uma tabela com Severidade / Evidência / Descrição / Impacto / Remediação
   - Marque severidades exatamente como: Critical, High, Medium, Low, Info
6. Deixe explícito no relatório se a análise foi surface-only, browser-auth, ou hybrid com source.

Comece por evidence/browser/BRIEF.md; se não existir, surface/BRIEF.md.
"""


def run_agent_analysis(ctx: ScanContext, *, model: str = "default") -> Path:
    apply_windows_sdk_patches()
    api_key = cursor_api_key()
    if not api_key:
        raise RuntimeError(
            "Defina CURSOR_API_KEY no arquivo .env (Dashboard Cursor → Integrations)."
        )

    scan_root = ctx.root / ctx.scan_id
    prompt = ANALYSIS_PROMPT.format(
        consent=ctx.target.consent,
        url=ctx.target.url,
        mode=ctx.target.mode.value,
    )

    if sys.platform == "win32":
        text = asyncio.run(
            _run_async(scan_root=scan_root, prompt=prompt, api_key=api_key, model=model)
        )
    else:
        text = _run_sync(scan_root=scan_root, prompt=prompt, api_key=api_key, model=model)

    report_path = ctx.report_dir / "REPORT.md"
    if not report_path.exists():
        report_path.write_text(
            "# Report (fallback — agent stdout)\n\n" + (text or ""),
            encoding="utf-8",
        )
    return report_path


def _run_sync(
    *,
    scan_root: Path,
    prompt: str,
    api_key: str,
    model: str,
) -> str:
    try:
        from cursor_sdk import Agent, LocalAgentOptions
    except ImportError as exc:
        raise RuntimeError("Instale cursor-sdk: pip install cursor-sdk") from exc

    with Agent.create(
        model=model,
        api_key=api_key,
        local=LocalAgentOptions(
            cwd=str(scan_root),
            setting_sources=["project", "user", "plugins"],
        ),
    ) as agent:
        run = agent.send(prompt)
        return run.text() or ""


async def _run_async(
    *,
    scan_root: Path,
    prompt: str,
    api_key: str,
    model: str,
) -> str:
    try:
        from cursor_sdk import LocalAgentOptions
        from cursor_sdk.asyncio import AsyncAgent, AsyncClient
    except ImportError as exc:
        raise RuntimeError("Instale cursor-sdk: pip install cursor-sdk") from exc

    async with await AsyncClient.launch_bridge(workspace=str(scan_root)) as client:
        agent = await AsyncAgent.create(
            client=client,
            model=model,
            api_key=api_key,
            local=LocalAgentOptions(
                cwd=str(scan_root),
                setting_sources=["project", "user", "plugins"],
            ),
        )
        try:
            run = await agent.send(prompt)
            return (await run.text()) or ""
        finally:
            await agent.close()
