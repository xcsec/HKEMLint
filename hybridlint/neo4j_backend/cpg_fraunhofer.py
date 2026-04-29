"""Invoke the Fraunhofer AISEC CPG library to build a Code Property Graph
and push it into Neo4j.

The Fraunhofer CPG tool (https://github.com/Fraunhofer-AISEC/cpg) is a
JVM application that parses C/C++, Go, Python, TypeScript via native
frontends and Rust via its LLVM IR frontend.  The ``cpg-neo4j`` sub-
project provides a CLI that writes the resulting graph directly into a
Neo4j instance.

Prerequisites
-------------
- Java >= 21
- Fraunhofer CPG ``cpg-neo4j`` distribution (built via ``gradlew installDist``)
- Neo4j >= 5 with the APOC plugin enabled

Environment
-----------
``CPG_NEO4J_BIN``  — path to the ``cpg-neo4j`` launcher script.
                     Defaults to ``cpg-neo4j`` on ``$PATH``.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from hybridlint.neo4j_backend.driver import Neo4jConnection


# ── defaults ────────────────────────────────────────────────────────

_DEFAULT_BIN = os.environ.get("CPG_NEO4J_BIN", "cpg-neo4j")

# Map file extensions to Fraunhofer CPG language frontend flags
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
    ".rs":  "cpg-language-llvm",       # Rust via LLVM IR frontend
    ".java": "cpg-language-java",
}


def _find_cpg_binary() -> str:
    """Resolve the ``cpg-neo4j`` binary path."""
    # 1. Explicit env var
    env = os.environ.get("CPG_NEO4J_BIN")
    if env and os.path.isfile(env):
        return env

    # 2. On $PATH
    which = shutil.which("cpg-neo4j")
    if which:
        return which

    # 3. Conventional Gradle installDist location (relative to project)
    for candidate in [
        "cpg-neo4j/build/install/cpg-neo4j/bin/cpg-neo4j",
        "../cpg/cpg-neo4j/build/install/cpg-neo4j/bin/cpg-neo4j",
    ]:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    return _DEFAULT_BIN   # let it fail with a clear error at runtime


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def build_cpg_fraunhofer(
    source_paths: Sequence[str | Path],
    conn: Neo4jConnection,
    *,
    purge_db: bool = True,
    extra_args: Sequence[str] = (),
    timeout: int = 300,
) -> None:
    """Run the Fraunhofer CPG tool on *source_paths* and push the
    resulting graph into Neo4j.

    Parameters
    ----------
    source_paths
        Files and / or directories to analyse.
    conn
        An open :class:`Neo4jConnection` — only used to extract
        connection parameters (host, port, user, password).
    purge_db
        If True (default), the tool erases the Neo4j database before
        writing.  Set to False when incrementally adding files.
    extra_args
        Additional CLI flags forwarded verbatim to ``cpg-neo4j``.
    timeout
        Maximum seconds to wait for the JVM process.
    """
    binary = _find_cpg_binary()

    # Parse host/port from bolt URI
    uri = conn._uri                       # e.g. "bolt://localhost:7687"
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

    # Append source paths
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
    """Convenience wrapper: analyse individual files."""
    build_cpg_fraunhofer(file_paths, conn, **kwargs)


def build_cpg_for_directory(
    directory: str | Path,
    conn: Neo4jConnection,
    **kwargs,
) -> None:
    """Convenience wrapper: analyse an entire directory."""
    build_cpg_fraunhofer([str(directory)], conn, **kwargs)
