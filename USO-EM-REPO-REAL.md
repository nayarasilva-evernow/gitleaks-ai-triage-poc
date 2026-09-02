# Usar a triagem em um repositório real

Esta branch (`reusable-action`) empacota a esteira como **composite action**. O
repositório real não copia código: ele referencia esta action no workflow.

A `main` segue sendo o POC (sample-app com secrets propositais).

## Passo a passo

### 1. Cadastrar a chave do Groq no repositório real

`Settings > Secrets and variables > Actions > New repository secret`

- Nome: `GROQ_API_KEY`
- Valor: a chave de https://console.groq.com/keys

### 2. Criar o workflow

Copie [`examples/secret-scan.yml`](examples/secret-scan.yml) para
`.github/workflows/secret-scan.yml` no repositório real. O mínimo é:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: nayarasilva-evernow/gitleaks-ai-triage-poc@reusable-action
  with:
    groq-api-key: ${{ secrets.GROQ_API_KEY }}
```

### 3. Abrir um PR de teste

Um PR com uma credencial fictícia (ex. `sk_live_` seguido de caracteres
aleatórios) deve reprovar o check. Um PR que só mexe em documentação deve
passar.

## Inputs

| Input | Default | Para que serve |
|-------|---------|----------------|
| `groq-api-key` | — | Chave da API Groq. Sem ela tudo vira `uncertain`. |
| `scan-scope` | `diff` | `diff` escaneia só os commits do PR/push; `full` varre o histórico. |
| `fail-on` | `true_positive` | Use `true_positive_or_uncertain` para um gate mais rígido. |
| `gitleaks-config` | auto | Caminho de um `.gitleaks.toml`. Vazio usa o do repositório, ou o padrão da action. |
| `triage-model` | `openai/gpt-oss-20b` | Modelo da triagem. |
| `triage-provider` | `groq` | `groq` (cloud) ou `ollama` (runner self-hosted). |
| `doc-chamado-url` | doc da action | URL do portal de chamados interno, exibida no Summary. |
| `doc-carta-url` | doc da action | URL do modelo de carta de aceite de risco. |
| `gitleaks-version` | `8.21.2` | Versão do CLI. |
| `python-version` | `3.12` | Versão do Python. |

## Outputs

`total`, `true-positives`, `false-positives`, `uncertain`, `gate-passed`,
`report-json`, `suggested-toml`.

Exemplo de uso em outro step:

```yaml
- if: steps.triage.outputs.true-positives != '0'
  run: echo "Findings bloqueantes: ${{ steps.triage.outputs.true-positives }}"
```

## Por que `scan-scope: diff` é o padrão

Cada finding do Gitleaks vira uma chamada ao Groq. Varrendo o histórico inteiro
de um repositório real são facilmente centenas de findings, o que estoura o
rate limit do free tier no meio da execução e deixa a run lenta.

Com `diff`, cada PR classifica apenas o que aquele PR introduziu. Se quiser a
varredura profunda, rode em um workflow separado e agendado:

```yaml
on:
  schedule:
    - cron: "0 3 * * 1"
  workflow_dispatch:

# ...
  with:
    groq-api-key: ${{ secrets.GROQ_API_KEY }}
    scan-scope: full
```

Quando o range de commits não está disponível (primeiro push da branch, clone
shallow, execução manual), a action escaneia apenas o commit atual e registra um
aviso — em vez de cair no histórico completo sem você pedir.

## Cuidado com artifacts

O `findings.json` contém os secrets **em claro**. O `triage-report.json` não:
guarda arquivo, linha, regra, veredicto, confiança e motivo. Suba apenas o
relatório e o `suggested_rules.toml`, como no exemplo.

Antes de chegar na IA, o secret já é mascarado (`triage/mask.py`) — o modelo vê
`sk_l****************3abc`, nunca o valor completo.

## Calibrar falsos positivos

Cada run gera `suggested_rules.toml` com allowlists derivadas dos falsos
positivos confirmados. Revise e mova os blocos úteis para o `.gitleaks.toml` do
repositório real. Isso reduz o volume de findings — e de chamadas à IA — nas
execuções seguintes.

## Validar a action antes de usar

O workflow `.github/workflows/action-selftest.yml` roda a action contra o
`sample-app` deste repositório e confirma que o gate bloqueia como esperado.
Ele dispara a cada push nesta branch e também manualmente:

```bash
gh workflow run "Self-test da action" --ref reusable-action
```

## Fixar uma versão

Referenciar `@reusable-action` acompanha a branch. Em produção, prefira uma tag:

```yaml
uses: nayarasilva-evernow/gitleaks-ai-triage-poc@v1
```
