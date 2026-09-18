# Hackteus

Cerca elétrica: collectors (estilo DevTools) + análise assistida. UI HTML/CSS/JS + API FastAPI.

Sem alvo padrão — cada scan depende da URL e do nível de acesso (anônimo, conta de teste, repo).

## Setup local

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate
# Linux:   source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
cp .env.example .env   # Windows: copy .env.example .env
```

Edite `.env` e coloque `CURSOR_API_KEY` se for usar análise assistida.

```bash
python main.py
```

UI local: http://127.0.0.1:8787

## Docker (VPS) — porta 4000

```bash
cp .env.example .env
# edite .env na VPS (nunca commite o .env)

docker compose up -d --build
```

Sobe em **http://SEU_IP:4000**

Dados persistentes (volumes Docker):
- `hackteus_data` → SQLite (`data/hackteus.db`)
- `hackteus_runs` → evidências (`runs/`)

Comandos úteis:

```bash
docker compose logs -f
docker compose restart
docker compose down
```

## CLI

```bash
python -m hackteus.cli scan --url https://alvo.exemplo --consent owner
python -m hackteus.cli scan --url https://alvo.exemplo --consent contract:ACME-001 --auth-user teste --auth-password '***' --agent
python -m hackteus.cli scan --url https://alvo.exemplo --repo https://github.com/org/repo.git --mode hybrid --agent
```

## Modos

| Modo | Quando |
|------|--------|
| `surface` | Só URL (caso mais comum) |
| `hybrid` | URL + repo liberado |
| `source` | Só Git |

Persistência:
- SQLite em `data/hackteus.db` — scans, briefs/reports e conversas
- Disco em `runs/<scan_id>/` — evidências
