"""SP1 -- Combiner Security checker.

Uses CPG dataflow edges to trace how two shared secrets are combined:

  SP1a: Combiner type — trace SECRET_BUF/CLASSICAL_OP/PQC_OP → COMBINER
        via dataflow. Classify combiner as KDF (PASS), XOR (FAIL),
        or concat (check downstream KDF via CFG reachability).
  SP1b: Input separation — for concat combiners, check if a length-prefix
        node exists on the dataflow path to the combiner.
  SP1c: SS ordering — use dataflow edge order to determine which SS
        enters the combiner first.
"""
from __future__ import annotations

import re

import networkx as nx

from hybridlint.cpg.models import (
    CPGNode,
    CryptoLabel,
    Finding,
    FunctionCPG,
    Severity,
    Verdict,
)
from hybridlint.checkers.base import BaseChecker

EXIT_ID = -1

# Combiner subtype classification from node text
_XOR_RE = re.compile(r"(?<!\w)(\^)(?!\^)|(\bxor_bytes\b)", re.IGNORECASE)
_KDF_RE = re.compile(
    r"\b(HKDF|hkdf_expand|hkdf_extract|SHA3|sha3_256|SHA256|sha256|"
    r"SHA512|sha512|HMAC|hmac|SHAKE256|shake256|BLAKE2|blake2b|"
    r"ssh_digest_buffer|tls13_generate_handshake_secret|"
    r"labeledExtract|labeledExpand|PairSplitPRF|combiner)\b"
)
_CONCAT_RE = re.compile(
    r"\b(memcpy|memmove|XMEMCPY|append|extend_from_slice|"
    r"copy\s*\(|CBB_add_bytes|sshbuf_put)\b"
)
_LEN_PREFIX_RE = re.compile(
    r"\b(len|length|size|sizeof|Size)\b.*\b(write|put|encode|push|add_u\d+)\b",
    re.IGNORECASE,
)


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    return text


def _classify_combiner(node: CPGNode) -> str:
    """Classify a COMBINER node as 'kdf', 'xor', 'concat', or 'unknown'."""
    code = _strip_comments(node.text)
    if _XOR_RE.search(code):
        return "xor"
    if _KDF_RE.search(code):
        return "kdf"
    if _CONCAT_RE.search(code):
        return "concat"
    # Check detail field set by labeler
    if node.detail:
        if "kdf" in node.detail.lower():
            return "kdf"
        if "xor" in node.detail.lower():
            return "xor"
        if "concat" in node.detail.lower():
            return "concat"
    return "unknown"


class SP1CombinerChecker(BaseChecker):
    """SP1: Check combiner security using CPG dataflow + CFG reachability."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)
        combiners = cpg.get_nodes_by_label(CryptoLabel.COMBINER)
        if not combiners:
            # No COMBINER nodes — try CPG dataflow XOR detection first,
            # then fall back to text matching if CPG yields nothing.
            cpg_xor = self._check_sp1a_cpg_xor(cpg, project)
            if cpg_xor:
                return cpg_xor
            return self._check_sp1a_text(cpg, project)

        findings = []

        # Build CFG digraph for reachability queries
        cfg = nx.DiGraph()
        for n in cpg.nodes.values():
            cfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type.startswith("cfg"):
                cfg.add_edge(e.src, e.dst)

        # Build dataflow digraph for tracing
        dfg = nx.DiGraph()
        for n in cpg.nodes.values():
            dfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type == "dataflow":
                dfg.add_edge(e.src, e.dst)

        # Find which combiners receive shared-secret data
        # (reachable from CLASSICAL_OP or PQC_OP via dataflow)
        ss_combiners = self._find_ss_combiners(cpg, dfg, combiners)

        for cnode in ss_combiners:
            # Skip comment nodes that were mislabeled as COMBINER
            code = _strip_comments(cnode.text)
            if not code.strip():
                continue
            findings.extend(self._check_sp1a(cpg, cfg, dfg, cnode, project))
            findings.extend(self._check_sp1b(cpg, dfg, cnode, project))
            findings.extend(self._check_sp1c(cpg, dfg, cnode, project))

        # SP1d: Context binding — check if combiner binds ct/pk/label
        # (runs once per function, not per combiner node)
        if ss_combiners:
            findings.extend(self._check_sp1d(cpg, ss_combiners, project))

        # CPG dataflow XOR detection, then text fallback if CPG yields nothing
        if not any(f.sub_property == "SP1a" and f.verdict == Verdict.FAIL for f in findings):
            cpg_xor = self._check_sp1a_cpg_xor(cpg, project)
            if cpg_xor:
                findings.extend(cpg_xor)
            else:
                findings.extend(self._check_sp1a_text(cpg, project))

        return findings

    # ── SP1a CPG-based XOR detection ────────────────────────────

    def _check_sp1a_cpg_xor(self, cpg: FunctionCPG,
                              project: str) -> list[Finding]:
        """CPG dataflow approach to detect XOR combiners.

        Scans all CPG nodes for XOR-related text, then confirms via
        dataflow predecessors that a shared secret feeds into the XOR.
        """
        _XOR_NODE_RE = re.compile(
            r"\bxor_assign\b|\bxor_bytes\b|\bxor\.Bytes\b|\^\s",
            re.IGNORECASE,
        )

        findings: list[Finding] = []
        crypto_labels = {CryptoLabel.SECRET_BUF, CryptoLabel.PQC_OP,
                         CryptoLabel.CLASSICAL_OP}

        for node in cpg.nodes.values():
            if not _XOR_NODE_RE.search(node.text):
                continue

            # Trace backwards along dataflow to see if a shared secret
            # feeds into this XOR node.
            pred_ids = cpg.get_dataflow_predecessors(node.id, max_depth=6)
            confirmed = any(
                cpg.nodes[pid].label in crypto_labels
                for pid in pred_ids
                if pid in cpg.nodes
            )

            if confirmed:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP1", sub_property="SP1a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"XOR combiner at L{node.line}: `{node.text[:80]}`. "
                        f"Dataflow confirms shared secret input. "
                        f"XOR is not IND-CCA preserving (Giacon et al.)."
                    ),
                    lines=[node.line],
                ))

        return findings

    # ── find combiners that actually merge shared secrets ─────────

    def _find_ss_combiners(self, cpg: FunctionCPG, dfg: nx.DiGraph,
                            combiners: list[CPGNode]) -> list[CPGNode]:
        """Filter combiners to those reachable from crypto ops via dataflow."""
        crypto_ids = {n.id for n in cpg.nodes.values()
                      if n.label in (CryptoLabel.CLASSICAL_OP, CryptoLabel.PQC_OP,
                                     CryptoLabel.SECRET_BUF, CryptoLabel.RNG_CALL)}
        combiner_ids = {c.id for c in combiners}

        result = []
        for cnode in combiners:
            # Check if any crypto op can reach this combiner via dataflow
            for cid in crypto_ids:
                if cid in dfg and cnode.id in dfg:
                    try:
                        if nx.has_path(dfg, cid, cnode.id):
                            result.append(cnode)
                            break
                    except nx.NetworkXError:
                        continue
        return result if result else combiners  # fallback: check all

    # ── SP1a: combiner type ──────────────────────────────────────

    def _check_sp1a(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                     dfg: nx.DiGraph, cnode: CPGNode,
                     project: str) -> list[Finding]:
        ctype = _classify_combiner(cnode)

        if ctype == "xor":
            return [Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1a",
                verdict=Verdict.FAIL, severity=Severity.HIGH,
                evidence=(
                    f"XOR combiner at L{cnode.line}: `{cnode.text[:80]}`. "
                    f"XOR is not IND-CCA preserving (Giacon et al.)."
                ),
                lines=[cnode.line],
            )]

        if ctype == "kdf":
            return [Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1a",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=f"KDF-based combiner at L{cnode.line}.",
                lines=[cnode.line],
            )]

        if ctype == "concat":
            # Check: is a KDF reachable downstream via CFG?
            kdf_downstream = self._find_downstream_kdf(cpg, cfg, cnode.id)
            if kdf_downstream:
                return [Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP1", sub_property="SP1a",
                    verdict=Verdict.PASS, severity=Severity.LOW,
                    evidence=(
                        f"Concat combiner at L{cnode.line}, "
                        f"followed by KDF at L{kdf_downstream.line}."
                    ),
                    lines=[cnode.line, kdf_downstream.line],
                )]
            return [Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1a",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"Concat combiner at L{cnode.line} with no downstream KDF "
                    f"in this function. Protocol-layer KDF may exist elsewhere."
                ),
                lines=[cnode.line],
            )]

        return [Finding(
            project=project,
            file_path=cpg.site.file_path,
            function_name=cpg.site.function_name,
            sp="SP1", sub_property="SP1a",
            verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
            evidence=f"Unrecognized combiner at L{cnode.line}: `{cnode.text[:60]}`",
            lines=[cnode.line],
        )]

    def _find_downstream_kdf(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                              start_id: int) -> CPGNode | None:
        """Find a KDF node reachable from start_id via CFG edges."""
        if start_id not in cfg:
            return None
        try:
            for nid in nx.descendants(cfg, start_id):
                node = cpg.nodes.get(nid)
                if node and _KDF_RE.search(_strip_comments(node.text)):
                    return node
        except nx.NetworkXError:
            pass
        return None

    # ── SP1b: input separation ───────────────────────────────────

    def _check_sp1b(self, cpg: FunctionCPG, dfg: nx.DiGraph,
                     cnode: CPGNode, project: str) -> list[Finding]:
        ctype = _classify_combiner(cnode)
        if ctype != "concat":
            return []

        # Walk dataflow predecessors of the combiner (up to 5 hops)
        # looking for a length-prefix node
        predecessors = set()
        stack = [(cnode.id, 0)]
        while stack:
            nid, depth = stack.pop()
            if nid in predecessors or depth > 5:
                continue
            predecessors.add(nid)
            # Walk backwards along dataflow
            for e in cpg.edges:
                if e.edge_type == "dataflow" and e.dst == nid:
                    stack.append((e.src, depth + 1))
            # Also walk backwards along CFG (for sequential predecessors)
            for pred_id, _ in cpg.get_cfg_predecessors(nid):
                if pred_id not in predecessors and depth < 3:
                    predecessors.add(pred_id)

        for pid in predecessors:
            pnode = cpg.nodes.get(pid)
            if pnode and _LEN_PREFIX_RE.search(pnode.text):
                return [Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP1", sub_property="SP1b",
                    verdict=Verdict.PASS, severity=Severity.LOW,
                    evidence=(
                        f"Length prefix at L{pnode.line} before "
                        f"concat at L{cnode.line}."
                    ),
                    lines=[pnode.line, cnode.line],
                )]

        return [Finding(
            project=project,
            file_path=cpg.site.file_path,
            function_name=cpg.site.function_name,
            sp="SP1", sub_property="SP1b",
            verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
            evidence=(
                f"No length prefix found before concat at L{cnode.line}."
            ),
            lines=[cnode.line],
        )]

    # ── SP1c: shared secret ordering ─────────────────────────────

    def _check_sp1c(self, cpg: FunctionCPG, dfg: nx.DiGraph,
                     cnode: CPGNode, project: str) -> list[Finding]:
        """Determine which SS enters the combiner first via dataflow ordering."""
        # Find dataflow predecessors of the combiner
        df_preds = []
        for e in cpg.edges:
            if e.edge_type == "dataflow" and e.dst == cnode.id:
                src = cpg.nodes.get(e.src)
                if src:
                    df_preds.append(src)

        # Classify predecessors as classical or PQC
        classical_preds = [n for n in df_preds
                           if n.label in (CryptoLabel.CLASSICAL_OP, CryptoLabel.SECRET_BUF)
                           and any(kw in n.text for kw in ("x25519", "X25519", "ecdh",
                                                            "ECDH", "ecc", "curve"))]
        pqc_preds = [n for n in df_preds
                     if n.label in (CryptoLabel.PQC_OP, CryptoLabel.SECRET_BUF)
                     and any(kw in n.text for kw in ("mlkem", "MLKEM", "kyber",
                                                      "Kyber", "kem", "pqc"))]

        if not classical_preds or not pqc_preds:
            return [Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1c",
                verdict=Verdict.UNCERTAIN, severity=Severity.LOW,
                evidence=(
                    f"Cannot determine SS ordering at combiner L{cnode.line}: "
                    f"classical predecessors={len(classical_preds)}, "
                    f"PQC predecessors={len(pqc_preds)}."
                ),
                lines=[cnode.line],
            )]

        # Determine ordering by line number (earlier = first in concat)
        first_classical = min(n.line for n in classical_preds)
        first_pqc = min(n.line for n in pqc_preds)
        order = "PQC first" if first_pqc < first_classical else "classical first"

        return [Finding(
            project=project,
            file_path=cpg.site.file_path,
            function_name=cpg.site.function_name,
            sp="SP1", sub_property="SP1c",
            verdict=Verdict.UNCERTAIN, severity=Severity.LOW,
            evidence=(
                f"Combiner at L{cnode.line}: {order} "
                f"(PQC L{first_pqc}, classical L{first_classical}). "
                f"Verify against named group spec."
            ),
            lines=[cnode.line],
        )]

    # ── SP1d: context binding completeness ───────────────────────

    # Regexes for classifying dataflow predecessor nodes (SP1d)
    _CT_RE = re.compile(
        r"\b(ciphertext|ct_|_ct|mlkem_ct|fst\.value|enc\.fst|"
        r"kem_ciphertext|kyber_ct|x25519_ciphertext)\b",
        re.IGNORECASE,
    )
    _PK_RE = re.compile(
        r"\b(public_key|pk_|_pk|encapsulation_key|x25519_public|"
        r"mlkem_pub|peer_pub|pkx)\b",
        re.IGNORECASE,
    )
    _LABEL_RE = re.compile(
        r"\b(label|domain|separator|xwing_label|"
        r"context_string|suite_id)\b|"
        r"\\\\\.//\^\\\\|"          # X-Wing label literal
        r"[\"'].*?KEM.*?[\"']",     # label string containing "KEM"
        re.IGNORECASE,
    )
    _ALGID_RE = re.compile(
        r"\b(alg_?id|algorithm|oid|suite|group_id|kem_id)\b",
        re.IGNORECASE,
    )

    def _check_sp1d(self, cpg: FunctionCPG,
                     combiners: list[CPGNode],
                     project: str) -> list[Finding]:
        """Check if the combiner binds context beyond just shared secrets.

        CFRG draft-ounsworth-cfrg-kem-combiners defines UniversalCombiner:
          KDF(ss1 || ss2 || ct1 || ct2 || ek1 || ek2 || algID || label)

        Uses CPG dataflow predecessors to determine which context elements
        flow into the combiner, falling back to text-window scanning when
        the dataflow graph is too sparse.
        """
        findings: list[Finding] = []

        # ── Step 1: gather dataflow predecessors for all combiner nodes ──
        pred_ids: set[int] = set()
        for c in combiners:
            pred_ids.update(cpg.get_dataflow_predecessors(c.id, max_depth=8))

        # Collect cleaned text for each predecessor node
        pred_texts: list[str] = []
        for pid in pred_ids:
            pnode = cpg.nodes.get(pid)
            if pnode:
                pred_texts.append(_strip_comments(pnode.text))

        # Also include combiner node texts themselves (they may reference
        # context elements inline, e.g. KDF(ss || ct || label))
        for c in combiners:
            pred_texts.append(_strip_comments(c.text))

        # ── Step 2: fallback when dataflow graph is sparse ───────────
        # Count non-OTHER predecessors (nodes with a meaningful crypto label)
        non_other_count = sum(
            1 for pid in pred_ids
            if (pnode := cpg.nodes.get(pid)) is not None
            and pnode.label != CryptoLabel.OTHER
        )

        if non_other_count < 3:
            # Dataflow graph too thin -- augment with text-window approach
            body = cpg.site.body_text
            body_lines = body.split("\n")
            for c in combiners:
                start = max(0, c.line - cpg.site.start_line - 10)
                end = min(len(body_lines), c.line - cpg.site.start_line + 10)
                pred_texts.append(" ".join(body_lines[start:end]))

        # ── Step 3: classify predecessor texts ───────────────────────
        binds_ct = any(self._CT_RE.search(t) for t in pred_texts)
        binds_pk = any(self._PK_RE.search(t) for t in pred_texts)
        binds_label = any(self._LABEL_RE.search(t) for t in pred_texts)
        binds_algid = any(self._ALGID_RE.search(t) for t in pred_texts)

        # ── Step 4: build finding ────────────────────────────────────
        ctype = _classify_combiner(combiners[0])
        bound_elements = []
        missing_elements = []

        if binds_ct:
            bound_elements.append("ciphertext")
        else:
            missing_elements.append("ciphertext")

        if binds_pk:
            bound_elements.append("public_key")
        else:
            missing_elements.append("public_key")

        if binds_label:
            bound_elements.append("label")
        else:
            missing_elements.append("label")

        if binds_algid:
            bound_elements.append("algorithm_id")
        else:
            missing_elements.append("algorithm_id")

        if not missing_elements:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1d",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=(
                    f"Combiner binds all context elements: "
                    f"{', '.join(bound_elements)}."
                ),
                lines=[combiners[0].line],
            ))
        elif ctype in ("concat", "unknown") and len(missing_elements) >= 3:
            # Raw concat with no context binding at all
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1d",
                verdict=Verdict.FAIL, severity=Severity.MEDIUM,
                evidence=(
                    f"Combiner at L{combiners[0].line} ({ctype}) has no context "
                    f"binding. Missing: {', '.join(missing_elements)}. "
                    f"CFRG UniversalCombiner requires ct+pk+algID+label. "
                    f"Protocol-layer KDF (TLS HKDF, SSH exchange hash) may "
                    f"partially mitigate via transcript binding."
                ),
                lines=[combiners[0].line],
            ))
        elif missing_elements:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP1", sub_property="SP1d",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"Combiner at L{combiners[0].line} binds "
                    f"{', '.join(bound_elements)} but missing "
                    f"{', '.join(missing_elements)}."
                ),
                lines=[combiners[0].line],
            ))

        return findings

    # ── SP1a text fallback: XOR in function body ─────────────────

    def _check_sp1a_text(self, cpg: FunctionCPG,
                          project: str) -> list[Finding]:
        """Text-based fallback for XOR combiner detection.
        Catches cases where CPG didn't expand deep enough (Rust if-let blocks).
        """
        body = cpg.site.body_text
        code = _strip_comments(body)
        findings = []

        # Look for XOR combining patterns in function body
        xor_patterns = [
            (re.compile(r"\bxor_assign\s*\(", re.IGNORECASE), "xor_assign"),
            (re.compile(r"\bxor_bytes\s*\(", re.IGNORECASE), "xor_bytes"),
            (re.compile(r"\bxor\.Bytes\s*\(", re.IGNORECASE), "xor.Bytes"),
        ]

        for pattern, name in xor_patterns:
            for m in pattern.finditer(code):
                # Verify it's combining shared secrets (not just random XOR)
                context = code[max(0, m.start()-200):m.end()+100]
                is_ss_xor = any(kw in context for kw in (
                    "shared_secret", "psk", "secret", "ss",
                    "decapsulate", "encapsulate", "kem",
                ))
                if is_ss_xor:
                    line_no = body[:m.start()].count("\n") + cpg.site.start_line
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        sp="SP1", sub_property="SP1a",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"XOR combiner '{name}' at L{line_no} used to combine "
                            f"shared secrets. XOR is not IND-CCA preserving."
                        ),
                        lines=[line_no],
                    ))

        return findings
