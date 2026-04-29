"""SP4 Negotiation Integrity checker.

Detects violations of hybrid negotiation integrity:
- SP4a: Default group config mixing hybrid + classical groups.
- SP4b: Client sending classical fallback key shares.
- SP4c: Missing PQ enforcement logic (flagged UNCERTAIN -- hard to automate).
- SP4d: Parameter binding errors (wrong curve/KEM for a named group).
"""
from __future__ import annotations

import re

from hybridlint.cpg.models import FunctionCPG, Finding, CryptoLabel, Verdict, Severity
from hybridlint.checkers.base import BaseChecker
from hybridlint.locator.keywords import (
    HYBRID_GROUP_IDS,
    CLASSICAL_GROUP_IDS,
    RNG_FUNCTIONS,
    COMBINER_KDF,
)

# Expected component bindings for hybrid named groups.
# Each entry maps a hybrid group ID pattern to the set of (classical, PQC)
# component identifiers that MUST both appear in the mapping body.
_EXPECTED_BINDINGS: dict[str, tuple[set[str], set[str]]] = {
    # SecP384r1MLKEM1024 variants
    "SecP384r1MLKEM1024": (
        {"P-384", "P384", "secp384r1", "CurveP384", "NID_secp384r1", "SECP384R1"},
        {"ML-KEM-1024", "MLKEM1024", "mlkem1024", "Kyber1024"},
    ),
    "SSL_GROUP_SECP384R1_MLKEM1024": (
        {"P-384", "P384", "secp384r1", "CurveP384", "NID_secp384r1", "SECP384R1"},
        {"ML-KEM-1024", "MLKEM1024", "mlkem1024", "Kyber1024"},
    ),
    # SecP256r1MLKEM768 variants
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
    # X25519MLKEM768 variants
    "X25519MLKEM768": (
        {"X25519", "x25519", "Curve25519", "curve25519"},
        {"ML-KEM-768", "MLKEM768", "mlkem768", "Kyber768"},
    ),
    "SSL_GROUP_X25519_MLKEM768": (
        {"X25519", "x25519", "Curve25519", "curve25519"},
        {"ML-KEM-768", "MLKEM768", "mlkem768", "Kyber768"},
    ),
}

# Regex for array / slice literal contents (greedy, single-line).
_ARRAY_LITERAL_RE = re.compile(
    r"[{\[\(]([^}\]\)]+)[}\]\)]",
)


class SP4NegotiationChecker(BaseChecker):
    """Check that TLS/SSH hybrid negotiation is configured correctly."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def check(self, cpg: FunctionCPG) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sp4a(cpg))
        findings.extend(self._check_sp4b(cpg))
        findings.extend(self._check_sp4c(cpg))
        findings.extend(self._check_sp4d(cpg))
        findings.extend(self._check_sp4f(cpg))
        return findings

    # ------------------------------------------------------------------
    # SP4a -- hybrid + classical groups in the same default config
    # ------------------------------------------------------------------
    def _check_sp4a(self, cpg: FunctionCPG) -> list[Finding]:
        config_nodes = cpg.get_nodes_by_label(CryptoLabel.GROUP_CONFIG)
        findings: list[Finding] = []

        for node in config_nodes:
            elements = self._extract_array_elements(node.text)
            hybrid_found: list[str] = []
            classical_found: list[str] = []

            for elem in elements:
                stripped = elem.strip()
                if any(hg in stripped for hg in HYBRID_GROUP_IDS):
                    hybrid_found.append(stripped)
                elif any(cg in stripped for cg in CLASSICAL_GROUP_IDS):
                    classical_found.append(stripped)

            if hybrid_found and classical_found:
                findings.append(self._make_finding(
                    cpg, "SP4a", Verdict.FAIL, Severity.HIGH,
                    "Default group configuration mixes hybrid and classical "
                    f"groups in the same array. "
                    f"Hybrid: {hybrid_found}; Classical: {classical_found}.",
                    lines=[node.line],
                ))
            elif hybrid_found and not classical_found:
                findings.append(self._make_finding(
                    cpg, "SP4a", Verdict.PASS, Severity.LOW,
                    "Group config contains only hybrid group IDs.",
                    lines=[node.line],
                ))
            elif classical_found and not hybrid_found:
                # Pure classical config -- not necessarily wrong, but worth
                # noting in a hybrid context.
                findings.append(self._make_finding(
                    cpg, "SP4a", Verdict.UNCERTAIN, Severity.MEDIUM,
                    "Group config contains only classical group IDs; "
                    "no hybrid groups present.",
                    lines=[node.line],
                ))

        return findings

    # ------------------------------------------------------------------
    # SP4b -- client sending classical fallback key shares
    # ------------------------------------------------------------------
    def _check_sp4b(self, cpg: FunctionCPG) -> list[Finding]:
        findings: list[Finding] = []
        body = cpg.site.body_text

        # Heuristic: look for functions that mention both a hybrid group ID
        # and a standalone classical group ID in a return/append context,
        # suggesting the client offers a classical fallback key share.
        hybrid_mentions = [hg for hg in HYBRID_GROUP_IDS if hg in body]
        classical_mentions = [cg for cg in CLASSICAL_GROUP_IDS if cg in body]

        if not hybrid_mentions or not classical_mentions:
            return findings

        # Check if classical IDs appear near return / append / push / add
        # statements, implying they are being sent as separate key shares.
        _SHARE_CONTEXT_RE = re.compile(
            r"(?:return|append|push|add|emplace|insert|keyShares)"
            r"[^;{}\n]{0,120}"
            r"(" + "|".join(re.escape(cg) for cg in classical_mentions) + r")",
            re.MULTILINE,
        )

        for match in _SHARE_CONTEXT_RE.finditer(body):
            line_no = body[:match.start()].count("\n") + cpg.site.start_line
            findings.append(self._make_finding(
                cpg, "SP4b", Verdict.FAIL, Severity.HIGH,
                f"Client appears to send a classical fallback key share "
                f"({match.group(1)}) alongside hybrid groups "
                f"({hybrid_mentions[0]}). A downgrade-capable attacker could "
                "strip the hybrid share.",
                lines=[line_no],
            ))

        if not findings and hybrid_mentions and classical_mentions:
            # Both kinds of IDs are present but not in return/append context.
            findings.append(self._make_finding(
                cpg, "SP4b", Verdict.UNCERTAIN, Severity.MEDIUM,
                "Function references both hybrid and classical group IDs "
                "but no clear key-share sending pattern was detected.",
            ))

        return findings

    # ------------------------------------------------------------------
    # SP4c -- missing PQ enforcement logic
    # ------------------------------------------------------------------
    def _check_sp4c(self, cpg: FunctionCPG) -> list[Finding]:
        """Flag as UNCERTAIN -- this sub-property is difficult to automate."""
        body = cpg.site.body_text

        # Look for any enforcement-related patterns (abort, error, reject
        # when PQ is not offered).
        enforcement_hints = [
            "must_use_pq", "require_pq", "pq_required", "pqc_required",
            "hybrid_required", "require_hybrid", "must_use_hybrid",
            "abort", "reject",
        ]
        found_hints = [h for h in enforcement_hints if h.lower() in body.lower()]

        if found_hints:
            return [self._make_finding(
                cpg, "SP4c", Verdict.UNCERTAIN, Severity.LOW,
                "Some PQ enforcement hints found "
                f"({', '.join(found_hints)}), but correctness cannot be "
                "fully verified automatically.",
            )]

        # No enforcement logic detected at all.
        return [self._make_finding(
            cpg, "SP4c", Verdict.UNCERTAIN, Severity.MEDIUM,
            "No PQ enforcement logic detected. Manual review recommended "
            "to ensure the server rejects non-hybrid handshakes when "
            "PQ protection is required.",
        )]

    # ------------------------------------------------------------------
    # SP4d -- parameter binding errors
    # ------------------------------------------------------------------
    def _check_sp4d(self, cpg: FunctionCPG) -> list[Finding]:
        findings: list[Finding] = []
        body = cpg.site.body_text

        # Collect PARAM_CONST CPG nodes once for all group IDs.
        param_const_nodes = cpg.get_nodes_by_label(CryptoLabel.PARAM_CONST)

        for group_id, (expected_classical, expected_pqc) in _EXPECTED_BINDINGS.items():
            if group_id not in body:
                continue

            # ── CPG dataflow approach (preferred) ──────────────────────
            # Find PARAM_CONST nodes whose text matches this hybrid group ID.
            matching_nodes = [
                n for n in param_const_nodes if group_id in n.text
            ]

            if matching_nodes:
                for node in matching_nodes:
                    successor_ids = cpg.get_dataflow_successors(
                        node.id, max_depth=8,
                    )
                    successor_texts = [
                        cpg.nodes[nid].text
                        for nid in successor_ids
                        if nid in cpg.nodes
                    ]

                    has_classical = any(
                        c in txt
                        for txt in successor_texts
                        for c in expected_classical
                    )
                    has_pqc = any(
                        p in txt
                        for txt in successor_texts
                        for p in expected_pqc
                    )

                    if has_classical and has_pqc:
                        # Dataflow confirms both components are bound.
                        continue

                    missing_parts: list[str] = []
                    if not has_classical:
                        missing_parts.append(
                            f"classical component (expected one of "
                            f"{sorted(expected_classical)[:3]}...)"
                        )
                    if not has_pqc:
                        missing_parts.append(
                            f"PQC component (expected one of "
                            f"{sorted(expected_pqc)[:3]}...)"
                        )

                    findings.append(self._make_finding(
                        cpg, "SP4d", Verdict.FAIL, Severity.HIGH,
                        f"Parameter binding for {group_id} is missing "
                        f"{' and '.join(missing_parts)} "
                        f"(verified via CPG dataflow from node {node.id}).",
                        lines=[node.line],
                    ))
                continue

            # ── Text-scan fallback ─────────────────────────────────────
            # No PARAM_CONST nodes found for this group_id; fall back to
            # the original text-region heuristic.
            for match in re.finditer(re.escape(group_id), body):
                region_start = match.start()
                region_end = min(len(body), match.end() + 500)
                region = body[region_start:region_end]

                has_classical = any(c in region for c in expected_classical)
                has_pqc = any(p in region for p in expected_pqc)

                if has_classical and has_pqc:
                    continue

                line_no = body[:match.start()].count("\n") + cpg.site.start_line
                missing_parts = []
                if not has_classical:
                    missing_parts.append(
                        f"classical component (expected one of "
                        f"{sorted(expected_classical)[:3]}...)"
                    )
                if not has_pqc:
                    missing_parts.append(
                        f"PQC component (expected one of "
                        f"{sorted(expected_pqc)[:3]}...)"
                    )

                findings.append(self._make_finding(
                    cpg, "SP4d", Verdict.FAIL, Severity.HIGH,
                    f"Parameter binding for {group_id} is missing "
                    f"{' and '.join(missing_parts)}.",
                    lines=[line_no],
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_array_elements(text: str) -> list[str]:
        """Extract comma-separated elements from an array/slice literal."""
        elements: list[str] = []
        for match in _ARRAY_LITERAL_RE.finditer(text):
            inner = match.group(1)
            elements.extend(inner.split(","))
        # If no array literal found, split the whole text on commas as a
        # fallback (handles multi-line node text).
        if not elements:
            elements = text.split(",")
        return elements

    # ------------------------------------------------------------------
    # SP4f -- key domain separation (SP 800-227 RS12)
    # ------------------------------------------------------------------
    def _check_sp4f(self, cpg: FunctionCPG) -> list[Finding]:
        """Detect violation of key domain separation:
        - Pattern A: Same ECDH private key used for both hybrid and standalone key shares
        - Pattern B: Hybrid key component exposed for standalone use via API
        """
        # CPG-first path: trace keygen outputs through dataflow
        cpg_findings = self._check_sp4f_cpg(cpg)
        if cpg_findings:
            return cpg_findings

        # Text-based fallback
        findings = []
        body = cpg.site.body_text
        lang = cpg.site.language.value

        # Pattern A: function returns both hybrid + standalone key shares
        # sharing the same private key variable
        # Go: return priv, []keyShare{{ke.id, shareData}, ecdhShares[0]}, nil
        if lang == "go":
            # Check if function returns multiple keyShare with both hybrid and standalone
            if re.search(r"keyShare\s*\{.*keyShare\s*\{", body, re.DOTALL):
                pass  # Too loose
            # More specific: "ecdhShares[0]" returned alongside hybrid share
            if "ecdhShares[0]" in body and any(hg in body for hg in HYBRID_GROUP_IDS):
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if "ecdhShares[0]" in l and "return" in l.lower()), 0)
                findings.append(self._make_finding(
                    cpg, "SP4f", Verdict.FAIL, Severity.MEDIUM,
                    "Hybrid key exchange returns standalone ECDH key share "
                    "(ecdhShares[0]) alongside hybrid share. Same ECDH private "
                    "key is used for both. Violates SP 800-227 RS12 key domain separation.",
                    [line_no] if line_no else [],
                ))

        # Pattern A variant: C/C++ returning multiple key shares
        # with component reuse across groups
        if lang in ("c", "cpp"):
            # AWS-LC/BoringSSL: same SSLKeyShare component reused
            if ("key_shares_[" in body
                    and any(hg in body for hg in HYBRID_GROUP_IDS)
                    and any(cg in body for cg in CLASSICAL_GROUP_IDS)):
                findings.append(self._make_finding(
                    cpg, "SP4f", Verdict.UNCERTAIN, Severity.MEDIUM,
                    "Hybrid key share stores component key_shares_ that may be "
                    "reused across hybrid and classical groups.",
                ))

        # Pattern B: Rust trait exposing complete_component() for standalone use
        if lang == "rust":
            if "complete_component" in body:
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if "complete_component" in l), 0)
                findings.append(self._make_finding(
                    cpg, "SP4f", Verdict.FAIL, Severity.MEDIUM,
                    "Hybrid key exchange exposes complete_component() API that allows "
                    "using only the classical component for a standalone key exchange. "
                    "Violates SP 800-227 RS12: hybrid key material must not be used "
                    "outside the hybrid context.",
                    [line_no] if line_no else [],
                ))

            # Also check: component() method exposing classical pub_key
            if re.search(r"fn\s+component\s*\(", body):
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if "fn component" in l), 0)
                findings.append(self._make_finding(
                    cpg, "SP4f", Verdict.FAIL, Severity.MEDIUM,
                    "Hybrid key exchange exposes component() method that extracts "
                    "the classical component's public key for standalone use.",
                    [line_no] if line_no else [],
                ))

        # Pattern B variant: Go/C struct with individually accessible key fields
        if lang == "go":
            # CIRCL: publicKey struct with first/second fields
            if re.search(r"type\s+\w*(?:Key|key)\w*\s+struct\s*\{", body):
                if re.search(r"first\s+kem\.\w+Key", body) and re.search(r"second\s+kem\.\w+Key", body):
                    findings.append(self._make_finding(
                        cpg, "SP4f", Verdict.UNCERTAIN, Severity.LOW,
                        "Hybrid key struct exposes individual component key fields "
                        "(first, second). Components may be extractable for standalone use.",
                    ))

        return findings

    # ------------------------------------------------------------------
    # SP4f CPG-first: trace keygen dataflow to hybrid / non-hybrid ctx
    # ------------------------------------------------------------------
    _KEYGEN_RE = re.compile(
        r"\b(keypair|keygen|GenerateKey|generate_key_pair)\b", re.IGNORECASE,
    )

    def _check_sp4f_cpg(self, cpg: FunctionCPG) -> list[Finding]:
        """CPG dataflow approach for key domain separation.

        Find CLASSICAL_OP keygen nodes, trace their outputs forward, and
        check whether the same keygen reaches both a hybrid context and a
        non-hybrid (standalone classical) context.
        """
        keygen_nodes = [
            n for n in cpg.get_nodes_by_label(CryptoLabel.CLASSICAL_OP)
            if self._KEYGEN_RE.search(n.text)
        ]
        if not keygen_nodes:
            return []

        findings: list[Finding] = []

        for kg_node in keygen_nodes:
            succ_ids = cpg.get_dataflow_successors(kg_node.id, max_depth=10)
            reaches_hybrid = False
            reaches_non_hybrid = False
            hybrid_evidence: str = ""
            non_hybrid_evidence: str = ""

            for sid in succ_ids:
                snode = cpg.nodes.get(sid)
                if snode is None:
                    continue

                text = snode.text

                # Hybrid context: node text contains a hybrid group ID,
                # or node is itself a COMBINER.
                if snode.label == CryptoLabel.COMBINER:
                    reaches_hybrid = True
                    hybrid_evidence = f"COMBINER at L{snode.line}"
                elif any(hg in text for hg in HYBRID_GROUP_IDS):
                    reaches_hybrid = True
                    hybrid_evidence = f"hybrid group ref at L{snode.line}"

                # Non-hybrid context: node text contains a standalone
                # classical group ID, or appears in a return / keyShare
                # without hybrid wrapping.
                if any(cg in text for cg in CLASSICAL_GROUP_IDS):
                    # Make sure this is not also a hybrid reference
                    if not any(hg in text for hg in HYBRID_GROUP_IDS):
                        reaches_non_hybrid = True
                        non_hybrid_evidence = (
                            f"classical group ref at L{snode.line}"
                        )
                if (not reaches_non_hybrid
                        and re.search(r"\b(return|keyShare)\b", text)
                        and not any(hg in text for hg in HYBRID_GROUP_IDS)):
                    reaches_non_hybrid = True
                    non_hybrid_evidence = (
                        f"return/keyShare without hybrid wrapping at "
                        f"L{snode.line}"
                    )

            if reaches_hybrid and reaches_non_hybrid:
                findings.append(self._make_finding(
                    cpg, "SP4f", Verdict.FAIL, Severity.HIGH,
                    f"Keygen at L{kg_node.line} (`{kg_node.text[:60]}`) "
                    f"feeds both {hybrid_evidence} and "
                    f"{non_hybrid_evidence}. Same classical key is used in "
                    f"hybrid and standalone contexts, violating SP 800-227 "
                    f"RS12 key domain separation.",
                    lines=[kg_node.line],
                ))

        return findings

    @staticmethod
    def _make_finding(
        cpg: FunctionCPG,
        sub_property: str,
        verdict: Verdict,
        severity: Severity,
        evidence: str,
        lines: list[int] | None = None,
    ) -> Finding:
        return Finding(
            project="",
            file_path=cpg.site.file_path,
            function_name=cpg.site.function_name,
            sp="SP4",
            sub_property=sub_property,
            verdict=verdict,
            severity=severity,
            evidence=evidence,
            lines=lines or [],
        )
