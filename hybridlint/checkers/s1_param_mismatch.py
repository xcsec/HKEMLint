"""S1-1 — Parameter Mismatch.

Graph query:
  1. Find PARAM nodes containing hybrid group IDs.
  2. Trace dataflow successors to KEYGEN / ENCAP / DECAP nodes.
  3. Verify component parameters match the expected binding
     (e.g., X25519MLKEM768 → X25519 + ML-KEM-768).
"""
from __future__ import annotations

import re

import networkx as nx

from hybridlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    Severity, Verdict,
)
from hybridlint.checkers.base import BaseChecker
from hybridlint.locator.keywords import HYBRID_GROUP_IDS

# Expected component bindings: hybrid group → (classical keywords, PQC keywords)
_EXPECTED_BINDINGS: dict[str, tuple[set[str], set[str]]] = {
    "SecP384r1MLKEM1024": (
        {"P-384", "P384", "secp384r1", "CurveP384", "NID_secp384r1", "SECP384R1"},
        {"ML-KEM-1024", "MLKEM1024", "mlkem1024", "Kyber1024"},
    ),
    "SSL_GROUP_SECP384R1_MLKEM1024": (
        {"P-384", "P384", "secp384r1", "CurveP384", "NID_secp384r1", "SECP384R1"},
        {"ML-KEM-1024", "MLKEM1024", "mlkem1024", "Kyber1024"},
    ),
    "SecP256r1MLKEM768": (
        {"P-256", "P256", "secp256r1", "CurveP256", "NID_X9_62_prime256v1",
         "prime256v1", "SECP256R1"},
        {"ML-KEM-768", "MLKEM768", "mlkem768", "Kyber768"},
    ),
    "SSL_GROUP_SECP256R1_MLKEM768": (
        {"P-256", "P256", "secp256r1", "CurveP256", "NID_X9_62_prime256v1",
         "prime256v1", "SECP256R1"},
        {"ML-KEM-768", "MLKEM768", "mlkem768", "Kyber768"},
    ),
    "X25519MLKEM768": (
        {"X25519", "x25519", "Curve25519", "curve25519"},
        {"ML-KEM-768", "MLKEM768", "mlkem768", "Kyber768"},
    ),
    "SSL_GROUP_X25519_MLKEM768": (
        {"X25519", "x25519", "Curve25519", "curve25519"},
        {"ML-KEM-768", "MLKEM768", "mlkem768", "Kyber768"},
    ),
}


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


class S1ParamMismatchChecker(BaseChecker):
    """S1-1: Detect parameter binding mismatch in hybrid named groups."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)
        findings: list[Finding] = []

        body = cpg.site.body_text
        param_nodes = cpg.get_nodes_by_op(OpLabel.PARAM)

        for group_id, (expected_classical, expected_pqc) in _EXPECTED_BINDINGS.items():
            if group_id not in body:
                continue

            # ── CPG dataflow approach ──────────────────────────────
            matching = [n for n in param_nodes if group_id in n.text]

            if matching:
                for node in matching:
                    succ_ids = cpg.get_dataflow_successors(node.id, max_depth=8)
                    succ_texts = [
                        cpg.nodes[nid].text
                        for nid in succ_ids if nid in cpg.nodes
                    ]

                    has_classical = any(
                        c in txt for txt in succ_texts for c in expected_classical
                    )
                    has_pqc = any(
                        p in txt for txt in succ_texts for p in expected_pqc
                    )

                    if has_classical and has_pqc:
                        continue

                    missing = []
                    if not has_classical:
                        missing.append(
                            f"classical ({sorted(expected_classical)[:3]}…)"
                        )
                    if not has_pqc:
                        missing.append(
                            f"PQC ({sorted(expected_pqc)[:3]}…)"
                        )

                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S1-1",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"Parameter binding for {group_id} missing "
                            f"{' and '.join(missing)} "
                            f"(CPG dataflow from L{node.line})."
                        ),
                        lines=[node.line],
                    ))
                continue

            # ── Text-scan fallback ─────────────────────────────────
            for match in re.finditer(re.escape(group_id), body):
                region = body[match.start():min(len(body), match.end() + 500)]

                has_classical = any(c in region for c in expected_classical)
                has_pqc = any(p in region for p in expected_pqc)

                if has_classical and has_pqc:
                    continue

                line_no = body[:match.start()].count("\n") + cpg.site.start_line
                missing = []
                if not has_classical:
                    missing.append(f"classical ({sorted(expected_classical)[:3]}…)")
                if not has_pqc:
                    missing.append(f"PQC ({sorted(expected_pqc)[:3]}…)")

                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S1-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Parameter binding for {group_id} missing "
                        f"{' and '.join(missing)} (text scan at L{line_no})."
                    ),
                    lines=[line_no],
                ))

        return findings
