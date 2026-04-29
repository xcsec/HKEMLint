"""Locate hybrid KEM code sites using keyword co-location."""
from __future__ import annotations
import os
from typing import Optional

from hybridlint.cpg.models import HybridSite, Language
from hybridlint.locator.keywords import (
    CLASSICAL_KEYWORDS, PQC_KEYWORDS, HYBRID_DIRECT, GROUP_CONFIG_KEYWORDS,
)
from hybridlint.locator.parser import detect_language, extract_functions

# Directories to skip during scanning
SKIP_DIRS = {
    ".git", "vendor", "third_party", "thirdparty", "external",
    "node_modules", "__pycache__", ".build", "build", "cmake-build",
    "testdata", "fuzz", "fuzzing",
}

# Source file extensions we care about
SOURCE_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
                     ".rs", ".go", ".java"}


def _has_any_keyword(text: str, keywords: set[str]) -> list[str]:
    """Return which keywords from the set appear in text."""
    return [kw for kw in keywords if kw in text]


def _is_test_file(file_path: str) -> bool:
    """Heuristic: is this a test file?"""
    base = os.path.basename(file_path).lower()
    parts = file_path.lower().split(os.sep)
    if any(p in ("test", "tests", "testing", "unittest") for p in parts):
        return True
    if base.endswith("_test.go") or base.endswith("_test.cc") or base.endswith("_test.c"):
        return True
    if base.startswith("test_") or base.endswith("_test.rs"):
        return True
    return False


def walk_source_files(project_path: str, include_tests: bool = False) -> list[str]:
    """Walk project directory and yield source file paths."""
    files = []
    for dirpath, dirnames, filenames in os.walk(project_path):
        # Prune skipped directories
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            full_path = os.path.join(dirpath, fname)
            if not include_tests and _is_test_file(full_path):
                continue
            files.append(full_path)
    return files


def _quick_keyword_scan(file_path: str) -> tuple[bool, bool, bool]:
    """Quick text scan to check if file contains relevant keywords.
    Returns (has_hybrid_direct, has_colocation, has_config).
    Much faster than parsing every file with tree-sitter.
    """
    try:
        with open(file_path, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return False, False, False

    has_direct = any(kw in text for kw in HYBRID_DIRECT)
    has_classical = any(kw in text for kw in CLASSICAL_KEYWORDS)
    has_pqc = any(kw in text for kw in PQC_KEYWORDS)
    has_config = any(kw in text for kw in GROUP_CONFIG_KEYWORDS)

    # Classical + PQC co-location
    has_coloc = has_classical and has_pqc

    # Dual-PQC co-location (e.g., ML-KEM + HQC in Mullvad)
    _PQC_A = {"ml_kem", "mlkem", "MLKEM", "MlKem", "kyber", "Kyber"}
    _PQC_B = {"hqc", "HQC", "hqc256", "sntrup", "SNTRUP", "ntru", "NTRU"}
    has_dual_pqc = (any(kw in text for kw in _PQC_A)
                    and any(kw in text for kw in _PQC_B))

    return has_direct, (has_coloc or has_dual_pqc), (has_config and (has_classical or has_pqc))


def find_hybrid_sites(project_path: str,
                      include_tests: bool = False) -> list[HybridSite]:
    """Find all hybrid KEM code sites in a project.

    Uses three strategies:
    1. Direct keyword match (HYBRID_DIRECT)
    2. Co-location (CLASSICAL + PQC in same function)
    3. Config detection (GROUP_CONFIG + any crypto keyword)
    """
    sites = []
    source_files = walk_source_files(project_path, include_tests)

    for file_path in source_files:
        # Quick scan to skip irrelevant files
        has_direct, has_coloc, has_config = _quick_keyword_scan(file_path)
        if not (has_direct or has_coloc or has_config):
            continue

        lang = detect_language(file_path)
        if lang is None:
            continue

        # Parse file and extract functions
        functions = extract_functions(file_path)

        for func in functions:
            body = func.body_text
            site = _classify_function(func, body, lang, file_path)
            if site is not None:
                sites.append(site)

    return sites


def _classify_function(func, body: str, lang: Language,
                       file_path: str) -> Optional[HybridSite]:
    """Classify a function as a hybrid site, or return None."""

    # Strategy 1: Direct hybrid keyword match
    direct_matches = _has_any_keyword(body, HYBRID_DIRECT)
    if direct_matches:
        return HybridSite(
            file_path=file_path,
            language=lang,
            function_name=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            body_text=body,
            match_strategy="direct",
            matched_keywords=direct_matches,
            ts_node=func.ts_node,
        )

    # Strategy 2a: Co-location (CLASSICAL ∩ PQC in same function)
    classical_hits = _has_any_keyword(body, CLASSICAL_KEYWORDS)
    pqc_hits = _has_any_keyword(body, PQC_KEYWORDS)
    if classical_hits and pqc_hits:
        return HybridSite(
            file_path=file_path,
            language=lang,
            function_name=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            body_text=body,
            match_strategy="colocation",
            matched_keywords=classical_hits + pqc_hits,
            ts_node=func.ts_node,
        )

    # Strategy 2b: Dual-PQC hybrid (two different PQC KEMs in same function)
    # e.g., Mullvad: ML-KEM + HQC
    _PQC_GROUP_A = {"ml_kem", "mlkem", "MLKEM", "MlKem", "kyber", "Kyber"}
    _PQC_GROUP_B = {"hqc", "HQC", "hqc256", "sntrup", "SNTRUP", "ntru", "NTRU"}
    group_a_hits = _has_any_keyword(body, _PQC_GROUP_A)
    group_b_hits = _has_any_keyword(body, _PQC_GROUP_B)
    if group_a_hits and group_b_hits:
        return HybridSite(
            file_path=file_path,
            language=lang,
            function_name=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            body_text=body,
            match_strategy="colocation",
            matched_keywords=group_a_hits + group_b_hits,
            ts_node=func.ts_node,
        )

    # Strategy 3: Config site (for SP4 downgrade/parameter analysis)
    config_hits = _has_any_keyword(body, GROUP_CONFIG_KEYWORDS)
    crypto_hits = _has_any_keyword(body, CLASSICAL_KEYWORDS | PQC_KEYWORDS | HYBRID_DIRECT)
    if config_hits and crypto_hits:
        return HybridSite(
            file_path=file_path,
            language=lang,
            function_name=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            body_text=body,
            match_strategy="config",
            matched_keywords=config_hits + crypto_hits,
            ts_node=func.ts_node,
        )

    return None
