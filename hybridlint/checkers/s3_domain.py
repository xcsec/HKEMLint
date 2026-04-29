"""S3 — Key / Randomness Independence.

S3-1  Key Domain Violation
      Graph query: Find KEYGEN(component=1) nodes. Trace ek_1/dk_1
      forward. Check if same key reaches both hybrid and non-hybrid
      contexts. Violates SP 800-227 RS12.

S3-2  Shared Seed Without KDF
      Graph query: Find RNG nodes. Trace forward to KEYGEN/ENCAP.
      If same RNG feeds both components without COMBINER(kdf) on
      the dataflow path → FAIL.
"""
from __future__ import annotations

import re
from collections import deque

import networkx as nx

from hybridlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    CryptoLabel, Severity, Verdict,
)
from hybridlint.checkers.base import BaseChecker
from hybridlint.locator.keywords import (
    HYBRID_GROUP_IDS, CLASSICAL_GROUP_IDS, COMBINER_KDF,
)

# Functions that internally generate fresh randomness
_IMPLICIT_RNG = re.compile(
    r"\b("
    r"kexc25519_keygen|X25519_keypair|"
    r"MLKEM768_generate_key|MLKEM1024_generate_key|"
    r"MLKEM768_encap|MLKEM1024_encap|"
    r"EVP_PKEY_keygen|wc_KyberKey_MakeKey|wc_KyberEncapsulate|"
    r"OQS_KEM_encaps|OQS_KEM_keypair|"
    r"crypto_kem_sntrup761_enc|crypto_kem_sntrup761_keypair|"
    r"libcrux_ml_kem_mlkem768_portable_generate_key_pair|"
    r"libcrux_ml_kem_mlkem768_portable_encapsulate|"
    r"GenerateKey|Encapsulate|generate_key|encapsulate"
    r")\s*\(",
)

_DECAPS_RE = re.compile(r"(decaps|decapsulate|_dec$|_dec[^a-z]|Decap)", re.IGNORECASE)

_KEYGEN_RE = re.compile(
    r"\b(keypair|keygen|GenerateKey|generate_key_pair)\b", re.IGNORECASE,
)

# Seed slicing patterns (direct split without KDF)
_SEED_SLICE_RES = [
    re.compile(
        r"(?:memcpy|memmove|XMEMCPY|copy)\s*\([^,]+,\s*"
        r"(\w*(?:seed|eseed|rnd|rand|entropy|ikm)\w*)\s*(?:\[|,)",
        re.IGNORECASE,
    ),
    re.compile(r"(\w*(?:seed|eseed|rnd|rand)\w*)\s*\[\s*\d*\s*:\s*\d*\s*\]", re.IGNORECASE),
    re.compile(r"(\w*(?:seed|eseed|rnd|rand)\w*)\s*\[\s*(?:\.\.|\d+\s*\.\.)", re.IGNORECASE),
]


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


def _finding(cpg: FunctionCPG, project: str, rule_id: str,
             verdict: Verdict, severity: Severity,
             evidence: str, lines: list[int] | None = None) -> Finding:
    return Finding(
        project=project,
        file_path=cpg.site.file_path,
        function_name=cpg.site.function_name,
        rule_id=rule_id,
        verdict=verdict, severity=severity,
        evidence=evidence, lines=lines or [],
    )


class S3DomainChecker(BaseChecker):
    """S3-1 Key Domain Violation + S3-2 Shared Seed Without KDF."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_s3_1(cpg))
        findings.extend(self._check_s3_2(cpg))
        return findings

    # ── S3-1: Key Domain Violation ──────────────────────────────────

    def _check_s3_1(self, cpg: FunctionCPG) -> list[Finding]:
        """Trace KEYGEN(comp=1) outputs. If same key reaches both hybrid
        and non-hybrid contexts → FAIL."""
        project = _project_name(cpg.site.file_path)

        # CPG dataflow approach
        keygen_nodes = [
            n for n in cpg.get_nodes_by_op(OpLabel.KEYGEN)
            if n.component == 1
        ]
        if not keygen_nodes:
            return []

        findings: list[Finding] = []
        for kg in keygen_nodes:
            succ_ids = cpg.get_dataflow_successors(kg.id, max_depth=10)
            reaches_hybrid = False
            reaches_non_hybrid = False
            hybrid_ev = ""
            non_hybrid_ev = ""

            for sid in succ_ids:
                snode = cpg.nodes.get(sid)
                if snode is None:
                    continue

                text = snode.text
                if snode.op_label == OpLabel.COMBINER:
                    reaches_hybrid = True
                    hybrid_ev = f"COMBINER at L{snode.line}"
                elif any(hg in text for hg in HYBRID_GROUP_IDS):
                    reaches_hybrid = True
                    hybrid_ev = f"hybrid group ref at L{snode.line}"

                if any(cg in text for cg in CLASSICAL_GROUP_IDS):
                    if not any(hg in text for hg in HYBRID_GROUP_IDS):
                        reaches_non_hybrid = True
                        non_hybrid_ev = f"classical group ref at L{snode.line}"
                if (not reaches_non_hybrid
                        and re.search(r"\b(return|keyShare)\b", text)
                        and not any(hg in text for hg in HYBRID_GROUP_IDS)):
                    reaches_non_hybrid = True
                    non_hybrid_ev = f"return/keyShare at L{snode.line}"

            if reaches_hybrid and reaches_non_hybrid:
                findings.append(_finding(
                    cpg, project, "S3-1",
                    Verdict.FAIL, Severity.HIGH,
                    f"KEYGEN at L{kg.line} feeds both {hybrid_ev} and "
                    f"{non_hybrid_ev}. Same classical key used in hybrid "
                    f"and standalone contexts (SP 800-227 RS12).",
                    [kg.line],
                ))

        # Text-based fallback
        if not findings:
            findings.extend(self._check_s3_1_text(cpg, project))

        return findings

    def _check_s3_1_text(self, cpg: FunctionCPG,
                          project: str) -> list[Finding]:
        """Text patterns for key domain violation."""
        findings: list[Finding] = []
        body = cpg.site.body_text
        lang = cpg.site.language.value

        # Go: ecdhShares[0] returned alongside hybrid share
        if lang == "go" and "ecdhShares[0]" in body:
            if any(hg in body for hg in HYBRID_GROUP_IDS):
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if "ecdhShares[0]" in l and "return" in l.lower()), 0)
                findings.append(_finding(
                    cpg, project, "S3-1",
                    Verdict.FAIL, Severity.MEDIUM,
                    "Returns standalone ECDH key share alongside hybrid share. "
                    "Same ECDH key used in both contexts.",
                    [line_no] if line_no else [],
                ))

        # Rust: complete_component() or component() exposes classical key
        if lang == "rust":
            if "complete_component" in body:
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if "complete_component" in l), 0)
                findings.append(_finding(
                    cpg, project, "S3-1",
                    Verdict.FAIL, Severity.MEDIUM,
                    "complete_component() API allows standalone classical "
                    "key exchange with hybrid key material.",
                    [line_no] if line_no else [],
                ))

        return findings

    # ── S3-2: Shared Seed Without KDF ───────────────────────────────

    def _check_s3_2(self, cpg: FunctionCPG) -> list[Finding]:
        """Check if single RNG feeds both components without KDF."""
        if _DECAPS_RE.search(cpg.site.function_name):
            return []  # decaps is deterministic

        project = _project_name(cpg.site.file_path)

        # Collect RNG nodes (explicit + implicit)
        rng_nodes = cpg.get_nodes_by_op(OpLabel.RNG)
        implicit_rng = [
            n for n in cpg.nodes.values()
            if n.id != -1 and n.op_label != OpLabel.RNG
            and _IMPLICIT_RNG.search(n.text)
        ]

        # If both components have implicit RNG → independent by definition
        implicit_c = any(n.component == 1 for n in implicit_rng)
        implicit_p = any(n.component == 2 for n in implicit_rng)
        if implicit_c and implicit_p:
            return []

        all_rng = rng_nodes + implicit_rng
        if not all_rng:
            return []

        # Multiple RNG sources → check if they feed different components
        if len(all_rng) >= 2:
            feeds = self._classify_rng_targets(cpg, all_rng)
            both = [r for r, (c, p) in feeds.items() if c and p]
            if both:
                src = cpg.nodes.get(both[0])
                return [_finding(
                    cpg, project, "S3-2",
                    Verdict.FAIL, Severity.HIGH,
                    f"RNG at L{src.line if src else '?'} feeds BOTH "
                    f"components via dataflow without KDF separation.",
                    [src.line] if src else [],
                )]
            return []  # separate RNG per component

        # Single RNG source → check KDF domain separation
        if len(rng_nodes) == 1 and not (implicit_c and implicit_p):
            rng = rng_nodes[0]
            path_c, path_p, kdf_c, kdf_p = \
                self._kdf_between_rng_and_components(cpg, rng.id)

            findings: list[Finding] = []
            if path_c and path_p:
                if kdf_c and kdf_p:
                    findings.append(_finding(
                        cpg, project, "S3-2",
                        Verdict.PASS, Severity.LOW,
                        f"Single RNG at L{rng.line} domain-separated "
                        f"via KDF on all paths.",
                        [rng.line],
                    ))
                else:
                    missing = []
                    if not kdf_c:
                        missing.append("classical")
                    if not kdf_p:
                        missing.append("PQC")
                    findings.append(_finding(
                        cpg, project, "S3-2",
                        Verdict.FAIL, Severity.HIGH,
                        f"Single RNG at L{rng.line} feeds both components; "
                        f"path to {', '.join(missing)} lacks KDF.",
                        [rng.line],
                    ))

            # Text pattern: direct seed slicing
            findings.extend(self._check_seed_slicing(cpg, project))
            return findings

        # Fallback: just check seed slicing
        return self._check_seed_slicing(cpg, project)

    def _classify_rng_targets(self, cpg: FunctionCPG,
                               rng_nodes: list[CPGNode]
                               ) -> dict[int, tuple[bool, bool]]:
        dfg = nx.DiGraph()
        for n in cpg.nodes.values():
            dfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type == "dataflow":
                dfg.add_edge(e.src, e.dst)

        result = {}
        for rng in rng_nodes:
            classical, pqc = False, False
            visited: set[int] = set()
            queue = deque([(rng.id, 0)])
            while queue:
                nid, depth = queue.popleft()
                if nid in visited or depth > 6:
                    continue
                visited.add(nid)
                node = cpg.nodes.get(nid)
                if node and nid != rng.id:
                    if node.component == 1:
                        classical = True
                    elif node.component == 2:
                        pqc = True
                if nid in dfg:
                    for succ in dfg.successors(nid):
                        queue.append((succ, depth + 1))
            result[rng.id] = (classical, pqc)
        return result

    def _kdf_between_rng_and_components(
        self, cpg: FunctionCPG, rng_id: int,
    ) -> tuple[bool, bool, bool, bool]:
        """Return (path_to_classical, path_to_pqc,
                   kdf_on_classical_path, kdf_on_pqc_path)."""
        comp1 = [n for n in cpg.nodes.values() if n.component == 1
                 and n.op_label in (OpLabel.KEYGEN, OpLabel.ENCAP)]
        comp2 = [n for n in cpg.nodes.values() if n.component == 2
                 and n.op_label in (OpLabel.KEYGEN, OpLabel.ENCAP)]

        dfg = nx.DiGraph()
        for n in cpg.nodes.values():
            dfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type == "dataflow":
                dfg.add_edge(e.src, e.dst)

        reachable: set[int] = set()
        q: deque[int] = deque([rng_id])
        while q:
            nid = q.popleft()
            if nid in reachable:
                continue
            reachable.add(nid)
            if nid in dfg:
                for s in dfg.successors(nid):
                    q.append(s)

        path_c = path_p = False
        kdf_c = kdf_p = True

        for c in comp1:
            if c.id not in reachable:
                continue
            path_c = True
            if not cpg.dataflow_path_has_label(rng_id, c.id, OpLabel.COMBINER):
                kdf_c = False

        for c in comp2:
            if c.id not in reachable:
                continue
            path_p = True
            if not cpg.dataflow_path_has_label(rng_id, c.id, OpLabel.COMBINER):
                kdf_p = False

        if not path_c:
            kdf_c = False
        if not path_p:
            kdf_p = False

        return path_c, path_p, kdf_c, kdf_p

    def _check_seed_slicing(self, cpg: FunctionCPG,
                             project: str) -> list[Finding]:
        body = cpg.site.body_text
        findings: list[Finding] = []
        for pattern in _SEED_SLICE_RES:
            for match in pattern.finditer(body):
                seed_var = match.group(1)
                preceding = body[:match.start()]
                seed_first = preceding.find(seed_var)
                if seed_first == -1:
                    continue
                between = body[seed_first:match.start()]
                has_kdf = any(kdf in between for kdf in COMBINER_KDF)
                if not has_kdf:
                    line = body[:match.start()].count("\n") + cpg.site.start_line
                    findings.append(_finding(
                        cpg, project, "S3-2",
                        Verdict.FAIL, Severity.HIGH,
                        f"Direct seed slicing of '{seed_var}' without KDF: "
                        f"`{match.group(0).strip()}`",
                        [line],
                    ))
        return findings
