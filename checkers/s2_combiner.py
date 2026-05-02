from __future__ import annotations

import re

import networkx as nx

from hkemlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    CryptoLabel, Severity, Verdict,
)
from hkemlint.checkers.base import BaseChecker

_XOR_RE = re.compile(r"(?<!\w)(\^)(?!\^)|(\bxor_bytes\b)|(\bxor_assign\b)", re.IGNORECASE)
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

_CT_RE = re.compile(
    r"\b(ciphertext|ct_|_ct|mlkem_ct|fst\.value|enc\.fst|"
    r"kem_ciphertext|kyber_ct|x25519_ciphertext|brace_ct)\b",
    re.IGNORECASE,
)
_PK_RE = re.compile(
    r"\b(public_key|pk_|_pk|encapsulation_key|x25519_public|"
    r"mlkem_pub|peer_pub|pkx|brace_ek)\b",
    re.IGNORECASE,
)
_LABEL_RE = re.compile(
    r"\b(label|domain|separator|xwing_label|"
    r"context_string|suite_id)\b|"
    r"\\\\\.//\^\\\\|"
    r"[\"'].*?KEM.*?[\"']",
    re.IGNORECASE,
)
_ALGID_RE = re.compile(
    r"\b(alg_?id|algorithm|oid|suite|group_id|kem_id)\b",
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
    code = _strip_comments(node.text)
    if _XOR_RE.search(code):
        return "xor"
    if _KDF_RE.search(code):
        return "kdf"
    if _CONCAT_RE.search(code):
        return "concat"
    if node.detail:
        d = node.detail.lower()
        if "kdf" in d:
            return "kdf"
        if "xor" in d:
            return "xor"
        if "concat" in d:
            return "concat"
    return "unknown"


class S2CombinerChecker(BaseChecker):

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)
        findings: list[Finding] = []

        combiners = cpg.get_nodes_by_op(OpLabel.COMBINER)

        if not combiners:
            xor_findings = self._detect_xor_cpg(cpg, project)
            if xor_findings:
                return xor_findings
            return self._detect_xor_text(cpg, project)

        cfg = nx.DiGraph()
        for n in cpg.nodes.values():
            cfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type.startswith("cfg"):
                cfg.add_edge(e.src, e.dst)

        dfg = nx.DiGraph()
        for n in cpg.nodes.values():
            dfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type == "dataflow":
                dfg.add_edge(e.src, e.dst)

        ss_combiners = self._find_ss_combiners(cpg, dfg, combiners)

        for cnode in ss_combiners:
            code = _strip_comments(cnode.text)
            if not code.strip():
                continue
            findings.extend(self._check_s2_1(cpg, cfg, dfg, cnode, project))

        if ss_combiners:
            findings.extend(self._check_s2_2(cpg, ss_combiners, project))

        if not any(f.rule_id == "S2-1" and f.verdict == Verdict.FAIL
                   for f in findings):
            xor = self._detect_xor_cpg(cpg, project)
            if xor:
                findings.extend(xor)
            else:
                findings.extend(self._detect_xor_text(cpg, project))

        return findings


    def _check_s2_1(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                     dfg: nx.DiGraph, cnode: CPGNode,
                     project: str) -> list[Finding]:
        ctype = _classify_combiner(cnode)

        if ctype == "xor":
            return [Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S2-1",
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
                rule_id="S2-1",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=f"KDF-based combiner at L{cnode.line}.",
                lines=[cnode.line],
            )]

        if ctype == "concat":
            kdf_down = self._find_downstream_kdf(cpg, cfg, cnode.id)
            if kdf_down:
                return [Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S2-1",
                    verdict=Verdict.PASS, severity=Severity.LOW,
                    evidence=(
                        f"Concat at L{cnode.line}, KDF downstream at "
                        f"L{kdf_down.line}."
                    ),
                    lines=[cnode.line, kdf_down.line],
                )]
            return [Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S2-1",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"Concat combiner at L{cnode.line} with no downstream "
                    f"KDF visible. Protocol-layer KDF may exist elsewhere."
                ),
                lines=[cnode.line],
            )]

        return []

    def _find_downstream_kdf(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                              start_id: int) -> CPGNode | None:
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

    def _find_ss_combiners(self, cpg: FunctionCPG, dfg: nx.DiGraph,
                            combiners: list[CPGNode]) -> list[CPGNode]:
        crypto_ids = {n.id for n in cpg.nodes.values()
                      if n.op_label in (OpLabel.ENCAP, OpLabel.DECAP,
                                        OpLabel.KEYGEN)
                      or n.val_label in (ValLabel.K_1, ValLabel.K_2)}
        result = []
        for cnode in combiners:
            for cid in crypto_ids:
                if cid in dfg and cnode.id in dfg:
                    try:
                        if nx.has_path(dfg, cid, cnode.id):
                            result.append(cnode)
                            break
                    except nx.NetworkXError:
                        continue
        return result if result else combiners


    def _check_s2_2(self, cpg: FunctionCPG,
                     combiners: list[CPGNode],
                     project: str) -> list[Finding]:
        pred_ids: set[int] = set()
        for c in combiners:
            pred_ids.update(cpg.get_dataflow_predecessors(c.id, max_depth=8))

        pred_texts = []
        for pid in pred_ids:
            pnode = cpg.nodes.get(pid)
            if pnode:
                pred_texts.append(_strip_comments(pnode.text))
        for c in combiners:
            pred_texts.append(_strip_comments(c.text))

        non_none = sum(
            1 for pid in pred_ids
            if (pn := cpg.nodes.get(pid)) and pn.op_label != OpLabel.NONE
        )
        if non_none < 3:
            body = cpg.site.body_text
            lines = body.split("\n")
            for c in combiners:
                start = max(0, c.line - cpg.site.start_line - 10)
                end = min(len(lines), c.line - cpg.site.start_line + 10)
                pred_texts.append(" ".join(lines[start:end]))

        binds_ct = any(_CT_RE.search(t) for t in pred_texts)
        binds_pk = any(_PK_RE.search(t) for t in pred_texts)
        binds_label = any(_LABEL_RE.search(t) for t in pred_texts)
        binds_algid = any(_ALGID_RE.search(t) for t in pred_texts)

        bound = []
        missing = []
        for name, present in [("ciphertext", binds_ct), ("public_key", binds_pk),
                               ("label", binds_label), ("algorithm_id", binds_algid)]:
            (bound if present else missing).append(name)

        findings: list[Finding] = []
        ctype = _classify_combiner(combiners[0])

        if not missing:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S2-2",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=f"Combiner binds all context: {', '.join(bound)}.",
                lines=[combiners[0].line],
            ))
        elif ctype in ("concat", "unknown") and len(missing) >= 3:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S2-2",
                verdict=Verdict.FAIL, severity=Severity.MEDIUM,
                evidence=(
                    f"Combiner at L{combiners[0].line} ({ctype}) has no "
                    f"context binding. Missing: {', '.join(missing)}. "
                    f"Protocol-layer KDF may partially mitigate."
                ),
                lines=[combiners[0].line],
            ))
        elif missing:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S2-2",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"Combiner binds {', '.join(bound)} but missing "
                    f"{', '.join(missing)}."
                ),
                lines=[combiners[0].line],
            ))

        return findings


    def _detect_xor_cpg(self, cpg: FunctionCPG,
                         project: str) -> list[Finding]:
        _XOR_NODE_RE = re.compile(
            r"\bxor_assign\b|\bxor_bytes\b|\bxor\.Bytes\b|\^\s",
            re.IGNORECASE,
        )
        findings: list[Finding] = []
        crypto_ops = {OpLabel.ENCAP, OpLabel.DECAP, OpLabel.KEYGEN}
        crypto_vals = {ValLabel.K_1, ValLabel.K_2}

        for node in cpg.nodes.values():
            if not _XOR_NODE_RE.search(node.text):
                continue
            pred_ids = cpg.get_dataflow_predecessors(node.id, max_depth=6)
            confirmed = any(
                (cpg.nodes[pid].op_label in crypto_ops
                 or cpg.nodes[pid].val_label in crypto_vals)
                for pid in pred_ids if pid in cpg.nodes
            )
            if confirmed:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S2-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"XOR combiner at L{node.line}: `{node.text[:80]}`. "
                        f"Dataflow confirms shared secret input."
                    ),
                    lines=[node.line],
                ))
        return findings

    def _detect_xor_text(self, cpg: FunctionCPG,
                          project: str) -> list[Finding]:
        body = cpg.site.body_text
        code = _strip_comments(body)
        findings: list[Finding] = []
        xor_patterns = [
            (re.compile(r"\bxor_assign\s*\(", re.IGNORECASE), "xor_assign"),
            (re.compile(r"\bxor_bytes\s*\(", re.IGNORECASE), "xor_bytes"),
            (re.compile(r"\bxor\.Bytes\s*\(", re.IGNORECASE), "xor.Bytes"),
        ]
        for pattern, name in xor_patterns:
            for m in pattern.finditer(code):
                context = code[max(0, m.start() - 200):m.end() + 100]
                is_ss = any(kw in context for kw in (
                    "shared_secret", "psk", "secret", "ss",
                    "decapsulate", "encapsulate", "kem",
                ))
                if is_ss:
                    line_no = body[:m.start()].count("\n") + cpg.site.start_line
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S2-1",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"XOR combiner '{name}' at L{line_no} used to "
                            f"combine shared secrets."
                        ),
                        lines=[line_no],
                    ))
        return findings
