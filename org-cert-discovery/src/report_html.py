from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from progress import ProgressLog


def write_executive_html(
    path: Path,
    *,
    charts_dir: Path,
    inventory_rows: List[dict],
    gitleaks_rows: List[dict],
    org: str,
    repos_scanned: int,
    repos_total: int,
    progress: ProgressLog,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    charts_dir.mkdir(parents=True, exist_ok=True)

    jks_rows = [
        r
        for r in inventory_rows
        if r.get("artifact_type") in {"JKS", "Keystore", "P12/PFX"}
    ]
    by_type = Counter(r.get("artifact_type") or "N/D" for r in inventory_rows)
    by_repo = Counter(r.get("repo") or "" for r in jks_rows)
    gl_by_cat = Counter(r.get("categoria_demanda") or "N/D" for r in gitleaks_rows)

    chart_type = charts_dir / "por_tipo.png"
    chart_repo = charts_dir / "top_repos_jks.png"
    chart_gl = charts_dir / "gitleaks_categoria.png"

    _bar_chart(
        chart_type,
        labels=list(by_type.keys()) or ["Nenhum"],
        values=list(by_type.values()) or [0],
        title="Artefatos encontrados (API read-only)",
        xlabel="Tipo",
    )
    top = by_repo.most_common(10)
    _bar_chart(
        chart_repo,
        labels=[k for k, _ in top] or ["Nenhum"],
        values=[v for _, v in top] or [0],
        title="Top repositórios com JKS/Keystore/P12",
        xlabel="Repositório",
        horizontal=True,
    )
    _bar_chart(
        chart_gl,
        labels=list(gl_by_cat.keys()) or ["Nenhum"],
        values=list(gl_by_cat.values()) or [0],
        title="Gitleaks — fatia cert/chave por categoria",
        xlabel="Categoria",
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    coverage = (
        f"{repos_scanned}/{repos_total}" if repos_total else f"{repos_scanned}"
    )
    pct = (100.0 * repos_scanned / repos_total) if repos_total else 0.0

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8"/>
  <title>Relatório executivo — certificados e JKS</title>
  <style>
    body {{ font-family: "Segoe UI", Tahoma, sans-serif; margin: 32px; color: #1b1b1b; background: #f7f8fa; }}
    h1 {{ margin-bottom: 4px; }}
    .sub {{ color: #555; margin-bottom: 24px; }}
    .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }}
    .card {{ background: #fff; border: 1px solid #dde1e6; border-radius: 8px; padding: 16px 18px; min-width: 180px; }}
    .card .n {{ font-size: 28px; font-weight: 700; }}
    .card .l {{ color: #555; font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    .panel {{ background: #fff; border: 1px solid #dde1e6; border-radius: 8px; padding: 12px; }}
    img {{ max-width: 100%; height: auto; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #dde1e6; padding: 8px 10px; text-align: left; font-size: 13px; }}
    th {{ background: #1f4e79; color: #fff; }}
    .note {{ background: #fff8e6; border: 1px solid #f0d78c; padding: 12px; border-radius: 8px; margin: 18px 0; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <h1>Visibilidade de certificados e JKS</h1>
  <div class="sub">Organização: <strong>{_esc(org)}</strong> · Gerado em {now} · Token: somente leitura</div>

  <div class="cards">
    <div class="card"><div class="n">{len(jks_rows)}</div><div class="l">JKS / Keystore / P12</div></div>
    <div class="card"><div class="n">{len(inventory_rows)}</div><div class="l">Arquivos no inventário API</div></div>
    <div class="card"><div class="n">{len(gitleaks_rows)}</div><div class="l">Gitleaks cert/chave</div></div>
    <div class="card"><div class="n">{coverage}</div><div class="l">Repos varridos ({pct:.1f}%)</div></div>
  </div>

  <div class="note">
    <strong>Limite desta entrega:</strong> localização + último autor do arquivo.
    Classificação de <em>autoassinado</em> / <em>wildcard</em> dentro de JKS
    não foi feita (exige abertura do keystore — fase 2). Nenhuma alteração foi
    realizada nos repositórios.
  </div>

  <div class="grid">
    <div class="panel"><img src="{_rel(path, chart_type)}" alt="Por tipo"/></div>
    <div class="panel"><img src="{_rel(path, chart_repo)}" alt="Top repos"/></div>
    <div class="panel"><img src="{_rel(path, chart_gl)}" alt="Gitleaks"/></div>
    <div class="panel">
      <h3>Top 10 repositórios (JKS/P12)</h3>
      <table>
        <tr><th>Repositório</th><th>Qtd</th></tr>
        {"".join(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in (top or [("—", 0)]))}
      </table>
    </div>
  </div>

  <p style="margin-top:24px;color:#666;font-size:12px;">
    Relatório automático read-only. Planilha detalhada: relatorio_certificados.xlsx
  </p>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
    progress.info(f"HTML executivo gerado: {path}")
    return path


def _rel(html_path: Path, asset: Path) -> str:
    try:
        return asset.relative_to(html_path.parent).as_posix()
    except ValueError:
        return asset.as_posix()


def _esc(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _bar_chart(
    path: Path,
    *,
    labels: list,
    values: list,
    title: str,
    xlabel: str,
    horizontal: bool = False,
) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    if horizontal:
        ax.barh(labels[::-1], values[::-1], color="#1f4e79")
        ax.set_xlabel("Quantidade")
    else:
        ax.bar(labels, values, color="#1f4e79")
        ax.set_xlabel(xlabel)
        ax.tick_params(axis="x", rotation=30)
        ax.set_ylabel("Quantidade")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
