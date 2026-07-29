from __future__ import annotations

from typing import Iterable, Optional, Set

from checkpoint import CheckpointStore
from github_readonly import GitHubReadOnlyClient, split_repo
from progress import ProgressLog


def list_org_repos(
    client: GitHubReadOnlyClient,
    store: CheckpointStore,
    *,
    org: str,
    include_forks: bool,
    include_archived: bool,
    progress: ProgressLog,
) -> list[dict]:
    if store.listing_complete():
        repos = store.load_repos()
        progress.info(
            f"Retomando listagem do checkpoint: {len(repos)} repositórios."
        )
        eligible = _filter_repos(repos, include_forks, include_archived)
        _mark_skipped_repos(store, repos, eligible, progress)
        return eligible

    progress.info(f"Listando repositórios (GET /orgs/{org}/repos)...")
    raw = client.get_paginated(
        f"/orgs/{org}/repos",
        params={"type": "all", "sort": "full_name"},
    )
    mapped = []
    for r in raw:
        mapped.append(
            {
                "full_name": r["full_name"],
                "default_branch": r.get("default_branch") or "main",
                "html_url": r.get("html_url") or "",
                "language": r.get("language") or "",
                "archived": bool(r.get("archived")),
                "fork": bool(r.get("fork")),
            }
        )
        if len(mapped) % 100 == 0:
            store.upsert_repos(mapped[-100:])
            progress.progress(len(mapped), 0, label="repos listados (paginando)")

    store.upsert_repos(mapped)
    store.mark_listing_complete()
    store.set_meta("org", org)
    progress.info(f"Listagem concluída: {len(mapped)} repositórios.")
    eligible = _filter_repos(mapped, include_forks, include_archived)
    _mark_skipped_repos(store, mapped, eligible, progress)
    return eligible


def _filter_repos(
    repos: list[dict], include_forks: bool, include_archived: bool
) -> list[dict]:
    out = []
    for r in repos:
        archived = bool(r.get("archived"))
        fork = bool(r.get("fork"))
        if not include_archived and archived:
            continue
        if not include_forks and fork:
            continue
        out.append(r)
    return out


def _mark_skipped_repos(
    store: CheckpointStore,
    all_repos: list[dict],
    eligible: list[dict],
    progress: ProgressLog,
) -> None:
    """Marca forks/arquivados como concluídos para o progresso refletir o escopo real."""
    eligible_names = {r["full_name"] for r in eligible}
    skipped = 0
    for r in all_repos:
        name = r["full_name"]
        if name in eligible_names:
            continue
        store.mark_tree_done(name, error="skipped: fork/archived fora do escopo")
        skipped += 1
    if skipped:
        progress.info(f"Repositórios fora do escopo (ignorados): {skipped}")


def _classify(path: str, keystore_exts: Set[str], all_exts: Set[str]) -> Optional[str]:
    lower = path.lower()
    for ext in sorted(all_exts, key=len, reverse=True):
        if lower.endswith(ext):
            if ext in keystore_exts:
                if ext in {".p12", ".pfx"}:
                    return "P12/PFX"
                if ext == ".keystore":
                    return "Keystore"
                return "JKS"
            return "Cert/Chave (arquivo)"
    return None


def inventory_keystores(
    client: GitHubReadOnlyClient,
    store: CheckpointStore,
    *,
    repos: list[dict],
    extensions: Set[str],
    keystore_exts: Set[str],
    progress: ProgressLog,
) -> list[dict]:
    pending = store.repos_pending_tree()
    # Intersect with current eligible set
    eligible = {r["full_name"] for r in repos}
    pending = [r for r in pending if r["full_name"] in eligible]

    total = store.count_repos_total()
    done = store.count_repos_done()
    progress.info(
        f"Varredura de árvores: pendentes={len(pending)} | "
        f"já concluídos={done}/{total}"
    )

    for idx, repo in enumerate(pending, start=1):
        full_name = repo["full_name"]
        branch = repo.get("default_branch") or "main"
        progress.progress(
            done + idx - 1,
            total,
            label=f"escaneando {full_name}",
        )
        try:
            _scan_repo_tree(
                client,
                store,
                full_name=full_name,
                branch=branch,
                html_url=repo.get("html_url") or "",
                extensions=extensions,
                keystore_exts=keystore_exts,
            )
            store.mark_tree_done(full_name)
        except Exception as exc:  # noqa: BLE001 — continua e registra
            store.mark_tree_done(full_name, error=str(exc)[:500])
            progress.warning(f"{full_name}: erro na árvore — {exc}")

        if idx % 10 == 0 or idx == len(pending):
            progress.progress(
                store.count_repos_done(),
                total,
                label=f"arquivos acumulados={store.count_files()}",
            )

    return store.load_inventory_rows()


def _scan_repo_tree(
    client: GitHubReadOnlyClient,
    store: CheckpointStore,
    *,
    full_name: str,
    branch: str,
    html_url: str,
    extensions: Set[str],
    keystore_exts: Set[str],
) -> None:
    owner, name = split_repo(full_name)
    # GET recursive tree via branch ref
    ref = client.get_json(f"/repos/{owner}/{name}/git/ref/heads/{branch}")
    if not ref:
        # tenta default sem ref (repo vazio)
        return
    sha = ref.get("object", {}).get("sha")
    if not sha:
        return
    tree = client.get_json(
        f"/repos/{owner}/{name}/git/trees/{sha}",
        params={"recursive": "1"},
    )
    if not tree:
        return
    for node in tree.get("tree") or []:
        if node.get("type") != "blob":
            continue
        path = node.get("path") or ""
        kind = _classify(path, keystore_exts, extensions)
        if not kind:
            continue
        file_url = f"{html_url}/blob/{branch}/{path}" if html_url else ""
        store.upsert_file(
            {
                "repo": full_name,
                "path": path,
                "sha": node.get("sha"),
                "size": node.get("size"),
                "html_url": file_url,
                "artifact_type": kind,
            }
        )


def enrich_authors(
    client: GitHubReadOnlyClient,
    store: CheckpointStore,
    rows: list[dict],
    *,
    progress: ProgressLog,
) -> list[dict]:
    pending = store.files_pending_author()
    total = store.count_files()
    done = store.count_authors_done()
    progress.info(
        f"Autores: pendentes={len(pending)} | já feitos={done}/{total}"
    )

    for idx, item in enumerate(pending, start=1):
        owner, name = split_repo(item["repo"])
        progress.progress(
            done + idx - 1,
            total,
            label=f"{item['repo']} :: {item['path']}",
        )
        try:
            commits = client.get_json(
                f"/repos/{owner}/{name}/commits",
                params={"path": item["path"], "per_page": 1},
            )
            if not commits:
                store.mark_author_done_empty(item["id"])
                continue
            c0 = commits[0]
            commit = c0.get("commit") or {}
            author = commit.get("author") or {}
            msg = (commit.get("message") or "").split("\n", 1)[0][:200]
            store.mark_author(
                item["id"],
                author_name=author.get("name") or "",
                author_email=author.get("email") or "",
                commit_date=author.get("date") or "",
                commit_sha=c0.get("sha") or "",
                commit_message=msg,
            )
        except Exception as exc:  # noqa: BLE001
            store.mark_author_done_empty(item["id"])
            progress.warning(
                f"Autor falhou {item['repo']}/{item['path']}: {exc}"
            )

        if idx % 20 == 0 or idx == len(pending):
            progress.progress(
                store.count_authors_done(),
                total,
                label="enriquecimento autores",
            )

    return store.load_inventory_rows()
