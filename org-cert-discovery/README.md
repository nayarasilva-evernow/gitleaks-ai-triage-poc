# Automação read-only — inventário JKS / certificados

Varre repositórios de uma organização no GitHub (ou GitHub Enterprise) usando **apenas HTTP GET**, localiza arquivos de keystore/certificado, enriquece com o **último autor do path**, opcionalmente filtra uma foto Gitleaks local, e gera:

- `data/output/relatorio_certificados.xlsx`
- `data/output/relatorio_executivo.html` (gráficos)
- `data/output/run.log`

## Requisitos do token

Somente leitura, por exemplo:

- Contents: **Read**
- Metadata: **Read**

**Não** use token com permissão de escrita. O cliente bloqueia qualquer método diferente de `GET`/`HEAD`.

## Setup

```powershell
cd org-cert-discovery
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Edite .env: GITHUB_TOKEN e GITHUB_ORG
```

Opcional no `config.yaml` ou `.env`:

- `GITLEAKS_EXCEL=C:\caminho\para\LEVANTAMENTO GITLEAKS junho 2026.xlsx`
- `GITHUB_API_URL=https://github.empresa.com/api/v3` (Enterprise)

## Executar

```powershell
python src\main.py
```

Retomar após queda de internet (mesmo comando — usa checkpoint SQLite):

```powershell
python src\main.py
```

Só processar Gitleaks local (sem API):

```powershell
python src\main.py --skip-github
```

Recomeçar do zero (apaga checkpoint):

```powershell
python src\main.py --reset-checkpoint
```

## Etapas (log)

1. `GITLEAKS` — filtro local da foto (se configurada)
2. `REPOS` — lista repositórios da org
3. `INVENTARIO` — árvore default de cada repo; paths `.jks`, `.keystore`, `.p12`, `.pfx` (+ certs se habilitado)
4. `AUTORES` — último commit por path
5. `RELATORIO` — Excel + HTML

O log mostra etapa, `Progresso: X/Y (Z%) | faltam: N`.

## O que este relatório NÃO faz

- Não altera repositórios
- Não abre JKS com senha
- Não classifica autoassinado/wildcard dentro do keystore (fase 2)

## Tempo

Depende do tamanho da org e do rate limit. Com ~milhares de repos, espere várias horas; o checkpoint permite pausar e continuar.
