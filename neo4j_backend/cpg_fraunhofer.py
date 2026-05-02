from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from hkemlint.neo4j_backend.driver import Neo4jConnection


_DEFAULT_BIN = os.environ.get("CPG_NEO4J_BIN", "cpg-neo4j")

_LANG_FRONTENDS = {
    ".c":   "cpg-language-cxx",
    ".h":   "cpg-language-cxx",
    ".cc":  "cpg-language-cxx",
    ".cpp": "cpg-language-cxx",
    ".cxx": "cpg-language-cxx",
    ".hpp": "cpg-language-cxx",
    ".go":  "cpg-language-go",
    ".py":  "cpg-language-python",
    ".ts":  "cpg-language-typescript",
    ".rs":  "cpg-language-llvm",
    ".java": "cpg-language-java",
}


def _find_cpg_binary() -> str:
    env = os.environ.get("CPG_NEO4J_BIN")
    if env and os.path.isfile(env):
        return env

    which = shutil.which("cpg-neo4j")
    if which:
        return which

    for candidate in [
        "cpg-neo4j/build/install/cpg-neo4j/bin/cpg-neo4j",
        "../cpg/cpg-neo4j/build/install/cpg-neo4j/bin/cpg-neo4j",
    ]:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    return _DEFAULT_BIN


def build_cpg_fraunhofer(
    source_paths: Sequence[str | Path],
    conn: Neo4jConnection,
    *,
    purge_db: bool = True,
    extra_args: Sequence[str] = (),
    timeout: int = 300,
) -> None:
    binary = _find_cpg_binary()

    uri = conn._uri
    host = "localhost"
    port = "7687"
    if "://" in uri:
        netloc = uri.split("://", 1)[1]
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
        else:
            host = netloc

    cmd: list[str] = [
        binary,
        "--host", host,
        "--port", port,
        "--user", conn._user,
        "--password", conn._password,
    ]

    if not purge_db:
        cmd.append("--no-purge-db")

    cmd.extend(extra_args)

    for p in source_paths:
        cmd.append(str(p))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"cpg-neo4j exited with code {result.returncode}.\n"
                f"stderr: {result.stderr[:2000]}"
            )
    except FileNotFoundError:
        raise RuntimeError(
            f"Fraunhofer CPG binary not found at '{binary}'.  "
            f"Set CPG_NEO4J_BIN or install cpg-neo4j on $PATH.  "
            f"See https://github.com/Fraunhofer-AISEC/cpg"
        )


def build_cpg_for_files(
    file_paths: Sequence[str | Path],
    conn: Neo4jConnection,
    **kwargs,
) -> None:
    build_cpg_fraunhofer(file_paths, conn, **kwargs)


def build_cpg_for_directory(
    directory: str | Path,
    conn: Neo4jConnection,
    **kwargs,
) -> None:
    build_cpg_fraunhofer([str(directory)], conn, **kwargs)
