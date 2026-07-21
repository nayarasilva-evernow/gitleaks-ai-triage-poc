# Gitleaks AI Triage POC

Pipeline de secret scanning com **Gitleaks** + triagem de falsos positivos via **Groq** (tier gratuito), e feedback para evoluir o `.gitleaks.toml`.

## Estrutura

```
sample-app/          # App de teste com secrets propositais (TP + FP)
triage/              # Script Python de classificação
.gitleaks.toml       # Regras + allowlists
.github/workflows/   # Esteira GitHub Actions
scripts/run_local.ps1
```

## Fluxo

1. Gitleaks gera `findings.json`
2. Heurística local elimina FPs óbvios (docs/tests/placeholders)
3. LLM (Groq/Ollama) classifica o restante: `true_positive` | `false_positive` | `uncertain`
4. Gate falha só com `true_positive`
5. `suggested_rules.toml` sugere allowlists a partir dos FPs

## IA gratuita

| Provider | Custo | Setup |
|----------|-------|--------|
| **Groq** (default) | Gratuito (free tier) | Key em https://console.groq.com/keys |
| **Ollama** | Gratuito (local) | `TRIAGE_PROVIDER=ollama` + Ollama rodando |

## Como testar localmente

### Pré-requisitos

- [Gitleaks](https://github.com/gitleaks/gitleaks#installing) no PATH
- Python 3.11+
- `GROQ_API_KEY` (gratuita)

### Rodar tudo

```powershell
$env:GROQ_API_KEY = "gsk-..."
.\scripts\run_local.ps1
```

### Só a triagem (com findings já gerados)

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
gitleaks detect --source . --config .gitleaks.toml --report-path findings.json --report-format json
$env:GROQ_API_KEY = "gsk-..."
.\.venv\Scripts\python -m triage --findings findings.json
```

## CI (GitHub Actions)

1. Configure o secret `GROQ_API_KEY` no repositório
2. Push / PR dispara `.github/workflows/secret-scan.yml`
3. Artifacts: `findings.json`, `triage-report.json`, `suggested_rules.toml`

## Sample-app (vulnerabilidades propositais)

| Arquivo | Tipo | Esperado |
|---------|------|----------|
| `sample-app/app/config.py` | Stripe `sk_live_...` | **true positive** |
| `sample-app/app/aws_client.py` | AWS keys | **true positive** |
| `sample-app/tests/test_auth.py` | mocks | false positive |
| `sample-app/docs/setup.md` | exemplos | false positive / allowlist |
| `sample-app/.env.example` | placeholders | allowlist |

Todos os valores são **fictícios**.
