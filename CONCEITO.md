# Hackteus — cerca elétrica (conceito)

> Ferramenta de **segurança autorizada / defensiva**: analisar sistemas **com consentimento** (próprios primeiro), achar superfícies fracas, priorizar remediação — **antes** de criminosos.

## Analogia

| Casa | Sistema |
|------|---------|
| Muro baixo | App exposto com secrets no JS, headers fracos, APIs abertas |
| Análise da rua | O que o DevTools já mostra (HTML/JS/network/source maps) |
| Cerca elétrica | Collectors + agente LLM → relatório e correção |
| Portão com chave | Só roda com alvo próprio ou autorização documentada |

## Dois modos (isso é o produto)

### Modo A — `surface` (sempre disponível)

Equivale ao que você faz hoje nas **ferramentas de desenvolvedor**:

- HTML, bundles JS/CSS, source maps (`.js.map`)
- Headers de resposta, cookies, redirecionamentos
- Requests de rede (XHR/fetch) capturados via Playwright
- Tokens/keys vazados no front, endpoints públicos, erros verbosos

**Não precisa de repositório.** É o modo B2B padrão quando a empresa não libera o Git.

### Modo B — `source` (quando há repo)

White-box no código (ex.: `oferteus` no GitHub): authz, injection, secrets no backend, dependências.

### Modo C — `hybrid` (alvo próprio / cliente que libera tudo)

`surface` + `source` → melhor sinal, menos falso positivo.

## Primeiro alvo (lab histórico)

Oferteus foi só o **primeiro teste** durante o desenvolvimento — **não é padrão do produto**.
Cada execução pede URL + consentimento (+ auth/repo conforme o acesso).

## Arquitetura

```
[consentimento: próprio | contrato]
              │
              ▼
     ┌────────────────┐
     │ Target config  │  url, repo?, mode
     └───────┬────────┘
             ▼
┌────────────────────────────┐
│ Collectors (sem LLM)       │
│  surface: http + Playwright│
│  source:  clone + static   │
└────────────┬───────────────┘
             ▼
      evidence/<scan_id>/
             │
             ▼
┌────────────────────────────┐
│ Cursor Agent (cursor-sdk)  │
│  cwd = evidence (+ repo)   │
│  prompt: achar riscos,     │
│  priorizar, sugerir fix    │
└────────────┬───────────────┘
             ▼
      reports/<scan_id>.md
```

## Camadas da cerca (ordem)

1. Secrets / keys no JS e source maps  
2. Headers / cookies / CORS / CSP / HSTS  
3. Endpoints e payloads visíveis no network  
4. Source (se houver) — SAST leve + secrets  
5. (fase 2) Sessão autenticada de **staging** com credenciais de teste  

Fora de escopo do produto: exploit PoC ofensivo, bypass ativo, coerção.

## Negócio

- **Seu uso:** cerca contínua nos seus deploys (oferteus = vitrine).  
- **B2B:** contrato → modo `surface` (e `source` se liberarem) → relatório → remediação opcional.  
- Consentimento **sempre antes** do scan.

## Stack

- Python 3.10+: orquestração, collectors, `cursor-sdk`
- Playwright: DevTools automatizado (network + scripts)
- httpx: headers, robots, assets
- Cursor Agent: interpretação das evidências (não substitui collectors)

## Roadmap

- **P0** — CLI `hackteus scan --url … [--repo …]`; collectors surface; report via agente  
- **P1** — prova de ownership / registro de consentimento; score  
- **P2** — CI nos seus repos; dashboard  
- **P3** — oferta B2B com escopo + NDA  

## Princípio hard

Só analisa o que você **possui** ou tem **autorização documentada**.
