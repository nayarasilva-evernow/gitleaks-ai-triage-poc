from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable


class CheckpointStore:
    """Persistência para retomar após queda de rede/interrupção."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS repos (
                full_name TEXT PRIMARY KEY,
                default_branch TEXT,
                html_url TEXT,
                language TEXT,
                archived INTEGER,
                fork INTEGER,
                listed INTEGER DEFAULT 1,
                tree_done INTEGER DEFAULT 0,
                tree_error TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL,
                path TEXT NOT NULL,
                sha TEXT,
                size INTEGER,
                html_url TEXT,
                artifact_type TEXT,
                author_name TEXT,
                author_email TEXT,
                commit_date TEXT,
                commit_sha TEXT,
                commit_message TEXT,
                author_done INTEGER DEFAULT 0,
                UNIQUE(repo, path)
            );
            """
        )
        self._conn.commit()

    def reset(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            "DELETE FROM meta; DELETE FROM repos; DELETE FROM files;"
        )
        self._conn.commit()

    def set_meta(self, key: str, value: Any) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        self._conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        if not row:
            return default
        return json.loads(row["value"])

    def upsert_repos(self, repos: Iterable[dict]) -> None:
        cur = self._conn.cursor()
        for r in repos:
            cur.execute(
                """
                INSERT INTO repos(full_name, default_branch, html_url, language, archived, fork, listed)
                VALUES(?,?,?,?,?,?,1)
                ON CONFLICT(full_name) DO UPDATE SET
                    default_branch=excluded.default_branch,
                    html_url=excluded.html_url,
                    language=excluded.language,
                    archived=excluded.archived,
                    fork=excluded.fork,
                    listed=1
                """,
                (
                    r["full_name"],
                    r.get("default_branch") or "main",
                    r.get("html_url") or "",
                    r.get("language") or "",
                    1 if r.get("archived") else 0,
                    1 if r.get("fork") else 0,
                ),
            )
        self._conn.commit()

    def mark_listing_complete(self) -> None:
        self.set_meta("listing_complete", True)

    def listing_complete(self) -> bool:
        return bool(self.get_meta("listing_complete", False))

    def load_repos(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT full_name, default_branch, html_url, language, archived, fork, tree_done "
            "FROM repos WHERE listed=1 ORDER BY full_name"
        ).fetchall()
        return [dict(r) for r in rows]

    def repos_pending_tree(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT full_name, default_branch, html_url, language "
            "FROM repos WHERE listed=1 AND tree_done=0 ORDER BY full_name"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_tree_done(self, full_name: str, error: str | None = None) -> None:
        self._conn.execute(
            "UPDATE repos SET tree_done=1, tree_error=? WHERE full_name=?",
            (error, full_name),
        )
        self._conn.commit()

    def count_repos_total(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM repos WHERE listed=1"
        ).fetchone()
        return int(row["c"]) if row else 0

    def count_repos_done(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM repos WHERE listed=1 AND tree_done=1"
        ).fetchone()
        return int(row["c"]) if row else 0

    def upsert_file(self, item: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO files(repo, path, sha, size, html_url, artifact_type)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(repo, path) DO UPDATE SET
                sha=excluded.sha,
                size=excluded.size,
                html_url=excluded.html_url,
                artifact_type=excluded.artifact_type
            """,
            (
                item["repo"],
                item["path"],
                item.get("sha"),
                item.get("size"),
                item.get("html_url"),
                item.get("artifact_type"),
            ),
        )
        self._conn.commit()

    def files_pending_author(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, repo, path, sha, size, html_url, artifact_type "
            "FROM files WHERE author_done=0 ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_author(
        self,
        file_id: int,
        author_name: str,
        author_email: str,
        commit_date: str,
        commit_sha: str,
        commit_message: str,
    ) -> None:
        self._conn.execute(
            """
            UPDATE files SET
                author_name=?, author_email=?, commit_date=?,
                commit_sha=?, commit_message=?, author_done=1
            WHERE id=?
            """,
            (
                author_name,
                author_email,
                commit_date,
                commit_sha,
                commit_message,
                file_id,
            ),
        )
        self._conn.commit()

    def mark_author_done_empty(self, file_id: int) -> None:
        self._conn.execute(
            "UPDATE files SET author_done=1 WHERE id=?", (file_id,)
        )
        self._conn.commit()

    def load_inventory_rows(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT repo, path, sha, size, html_url, artifact_type,
                   author_name, author_email, commit_date, commit_sha, commit_message,
                   author_done
            FROM files ORDER BY repo, path
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def count_files(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM files").fetchone()
        return int(row["c"]) if row else 0

    def count_authors_done(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM files WHERE author_done=1"
        ).fetchone()
        return int(row["c"]) if row else 0
