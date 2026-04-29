"""S6-1 — Silent Single-KEM Fallback.

Graph query:
  1. Find ERROR_CHECK nodes after ENCAP/DECAP(component=2).
  2. On the error-handling CFG path, check if K_1 is used as the
     final output (reaches return/output without COMBINER).
  3. Also check if the error handler aborts or silently continues.

If PQC failure leads to using classical-only key → FAIL.
"""
from __future__ import annotations

import re

import networkx as nx

from hybridlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    CryptoLabel, Severity, Verdict,
)
from hybridlint.checkers.base import BaseChecker

_ABORT_RE = re.compile(
    r"\b(goto\s+\w+|return\s+(-?\d+|err|error|ret|NULL|false|FAILURE|"
    r"BAD_FUNC_ARG|MEMORY_E|WOLFSSL_FAILURE|SSH_ERR_|S2N_ERR_)|"
    r"abort\s*\(|exit\s*\(|panic\s*\()",
    re.IGNORECASE,
)

_HYBRID_FUNC_RE = re.compile(
    r"(hybrid|Hybrid|HYBRID|pqc_hybrid|ProcessPqcHybrid|"
    r"mlkem768x25519|sntrup761x25519|X25519MLKEM|xwing|XWing|"
    r"KeyAgreeEcdhMlKem|EcdhMlKem|ecdh_mlkem|"
    r"HybridKeyExchange|hybridKeyExchange|"
    r"Encapsulate|Decapsulate|encapsulate|decapsulate|"
    r"combiner|Combiner|SplitPRF|PairSplitPRF|"
    r"oqs_hyb_kem|oqs_evp_kem|"
    r"KeyAgree|SendKexDhReply|key_share|use_key_share|"
    r"Generate|Encap|Decap|Accept|Finish)",
    re.IGNORECASE,
)


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


class S6FallbackChecker(BaseChecker):
    """S6-1: Silent single-KEM fallback on PQC failure."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)

        if cpg.site.match_strategy not in ("direct", "colocation"):
            return []
        if not _HYBRID_FUNC_RE.search(cpg.site.function_name):
            return []

        findings: list[Finding] = []

        # Find PQC operation nodes (encap or decap)
        pqc_ops = [n for n in cpg.nodes.values()
                   if n.component == 2
                   and n.op_label in (OpLabel.ENCAP, OpLabel.DECAP)
                   and "(" in n.text]

        if not pqc_ops:
            # Fallback: use legacy PQC_OP label
            pqc_ops = [n for n in cpg.get_nodes_by_label(CryptoLabel.PQC_OP)
                       if "(" in n.text]

        if not pqc_ops:
            return findings

        pqc_max_line = max(n.line for n in pqc_ops)

        # Find error checks AFTER PQC operation
        error_checks = [n for n in cpg.get_nodes_by_op(OpLabel.ERROR_CHECK)
                        if n.line >= pqc_max_line]

        if not error_checks:
            return findings

        # Build CFG
        cfg = nx.DiGraph()
        for n in cpg.nodes.values():
            cfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type.startswith("cfg"):
                cfg.add_edge(e.src, e.dst)

        # For each error check, examine the error handler branch
        for ec in error_checks:
            handler_texts = []
            for succ_id, etype in cpg.get_cfg_successors(ec.id):
                succ = cpg.nodes.get(succ_id)
                if succ:
                    handler_texts.append(succ.text)
                    # Also check next hop
                    for s2_id, _ in cpg.get_cfg_successors(succ_id):
                        s2 = cpg.nodes.get(s2_id)
                        if s2:
                            handler_texts.append(s2.text)

            combined = " ".join(handler_texts)

            if _ABORT_RE.search(combined):
                # Error handler aborts — good
                continue

            # Check if error handler uses K_1 as output (fallback)
            # Look for: return/output using classical-only secret
            fallback_patterns = [
                # Uses classical shared secret directly as result
                re.compile(r"\b(return|output|result)\b.*\b(x25519|ecdh|classical|dh)\b",
                           re.IGNORECASE),
                # Continues execution without combining
                re.compile(r"\bcontinue\b"),
                # Sets a flag to skip PQC component
                re.compile(r"\b(skip_pqc|pqc_disabled|use_classical_only)\b",
                           re.IGNORECASE),
            ]

            is_fallback = any(p.search(combined) for p in fallback_patterns)

            if is_fallback:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S6-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"PQC error check at L{ec.line}: handler does not "
                        f"abort. May silently fall back to classical-only "
                        f"shared secret."
                    ),
                    lines=[ec.line],
                ))
            else:
                # Can't confirm the handler aborts
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S6-1",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"PQC error check at L{ec.line}: cannot confirm "
                        f"handler aborts. May continue with classical-only key."
                    ),
                    lines=[ec.line],
                ))

        # Text-based check: look for explicit fallback patterns in body
        findings.extend(self._text_fallback_check(cpg, project))

        return findings

    def _text_fallback_check(self, cpg: FunctionCPG,
                              project: str) -> list[Finding]:
        """Detect explicit fallback code patterns."""
        body = cpg.site.body_text
        findings: list[Finding] = []

        # Pattern: "if PQC fails, use classical only"
        fallback_pats = [
            (re.compile(r"(?:if|when).*(?:kem|pqc|mlkem|kyber).*fail.*(?:use|return|fall\s*back).*(?:classical|ecdh|x25519)",
                         re.IGNORECASE | re.DOTALL),
             "Explicit classical fallback on PQC failure"),
            (re.compile(r"(?:pqc|kem|mlkem)_?(?:optional|disabled|skip)",
                         re.IGNORECASE),
             "PQC component marked as optional/skippable"),
        ]

        for pat, desc in fallback_pats:
            m = pat.search(body)
            if m:
                line_no = body[:m.start()].count("\n") + cpg.site.start_line
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S6-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=f"{desc} at L{line_no}.",
                    lines=[line_no],
                ))

        return findings
