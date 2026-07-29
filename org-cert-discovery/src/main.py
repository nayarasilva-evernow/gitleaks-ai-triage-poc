"""
Automação read-only: inventário de JKS/certs em repositórios GitHub/GHE.

- Apenas HTTP GET
- Checkpoint para retomar após queda de rede
- Rate limit respeitado
- Excel + relatório HTML executivo com gráficos
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Permite `python src/main.py` e `python run.py`
_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv

from checkpoint import CheckpointStore
from config_loader import load_config, project_root
from gitleaks_filter import filter_gitleaks_excel
from github_readonly import GitHubReadOnlyClient
from inventory import enrich_authors, inventory_keystores, list_org_repos
from progress import ProgressLog
from report_excel import write_excel
from report_html import write_executive_html

log = logging.getLogger("org_cert_discovery")


def _setup_logging(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / "run.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
    for h in list(root.handlers):
        root.removeHandler(h)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(sh)
    root.addHandler(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Varredura read-only de JKS/certs em repositórios (GitHub/GHE)."
    )
    parser.add_argument(
        "--config",
        default=str(project_root() / "config.yaml"),
        help="Caminho do config.yaml",
    )
    parser.add_argument(
        "--skip-github",
        action="store_true",
        help="Não chama a API GitHub; só processa Excel Gitleaks (se configurado) e gera relatório.",
    )
    parser.add_argument(
        "--skip-gitleaks",
        action="store_true",
        help="Não processa a foto Gitleaks.",
    )
    parser.add_argument(
        "--reset-checkpoint",
        action="store_true",
        help="Apaga o checkpoint e recomeça do zero (ainda assim só leitura na API).",
    )
    args = parser.parse_args(argv)

    root = project_root()
    load_dotenv(root / ".env")
    cfg = load_config(Path(args.config))

    output_dir = root / cfg["paths"]["output_dir"]
    checkpoint_dir = root / cfg["paths"]["checkpoint_dir"]
    _setup_logging(output_dir)

    progress = ProgressLog(log)
    store = CheckpointStore(checkpoint_dir / "state.sqlite3")
    if args.reset_checkpoint:
        store.reset()
        progress.info("Checkpoint apagado. Reinício limpo.")

    progress.stage("INICIO", "Automação read-only — nenhuma alteração será feita nos repositórios.")

    gitleaks_rows: list[dict] = []
    inventory_rows: list[dict] = []
    repos: list[dict] = []

    # --- Etapa: Gitleaks local (sem token) ---
    if not args.skip_gitleaks and cfg.get("gitleaks_excel"):
        progress.stage("GITLEAKS", "Filtrando foto Gitleaks local (sem API).")
        gitleaks_path = Path(cfg["gitleaks_excel"])
        if not gitleaks_path.is_absolute():
            gitleaks_path = root / gitleaks_path
        gitleaks_rows = filter_gitleaks_excel(
            gitleaks_path,
            keywords=cfg["gitleaks_cert_keywords"],
            progress=progress,
        )
        progress.info(f"Gitleaks: {len(gitleaks_rows)} apontamentos de cert/chave.")
    else:
        progress.info("Etapa Gitleaks ignorada (não configurada ou --skip-gitleaks).")

    # --- Etapas GitHub (somente GET) ---
    if not args.skip_github:
        client = GitHubReadOnlyClient(
            rate_limit_floor=cfg["rate_limit_floor"],
            min_interval=cfg["min_request_interval_seconds"],
            progress=progress,
        )
        org = cfg["org"]
        progress.stage("REPOS", f"Listando repositórios da organização '{org}' (GET).")
        repos = list_org_repos(
            client,
            store,
            org=org,
            include_forks=cfg["include_forks"],
            include_archived=cfg["include_archived"],
            progress=progress,
        )
        progress.info(f"Repositórios elegíveis: {len(repos)}")

        extensions = set(cfg["keystore_extensions"])
        if cfg.get("include_cert_files"):
            extensions |= set(cfg["cert_file_extensions"])

        progress.stage("INVENTARIO", "Varrendo árvores default (GET) em busca de keystores/certs.")
        inventory_rows = inventory_keystores(
            client,
            store,
            repos=repos,
            extensions=extensions,
            keystore_exts=set(cfg["keystore_extensions"]),
            progress=progress,
        )
        progress.info(f"Arquivos candidatos encontrados: {len(inventory_rows)}")

        progress.stage("AUTORES", "Enriquecendo com último commit por path (GET).")
        inventory_rows = enrich_authors(client, store, inventory_rows, progress=progress)
        progress.info("Enriquecimento de autores concluído.")
    else:
        progress.info("Etapa GitHub ignorada (--skip-github).")
        # Retoma inventário já checkpointado, se houver
        inventory_rows = store.load_inventory_rows()
        if inventory_rows:
            progress.info(f"Carregados {len(inventory_rows)} itens do checkpoint.")

    progress.stage("RELATORIO", "Gerando Excel e HTML executivo.")
    excel_path = output_dir / "relatorio_certificados.xlsx"
    html_path = output_dir / "relatorio_executivo.html"
    charts_dir = output_dir / "charts"

    write_excel(
        excel_path,
        inventory_rows=inventory_rows,
        gitleaks_rows=gitleaks_rows,
        org=cfg.get("org", ""),
        progress=progress,
    )
    write_executive_html(
        html_path,
        charts_dir=charts_dir,
        inventory_rows=inventory_rows,
        gitleaks_rows=gitleaks_rows,
        org=cfg.get("org", ""),
        repos_scanned=store.count_repos_done(),
        repos_total=store.count_repos_total() or len(repos),
        progress=progress,
    )

    progress.stage(
        "FIM",
        f"Concluído. Excel: {excel_path} | Executivo: {html_path} | Log: {output_dir / 'run.log'}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
