from __future__ import annotations

import re

import networkx as nx

from hkemlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    CryptoLabel, Severity, Verdict,
)
from hkemlint.checkers.base import BaseChecker

EXIT_ID = -1

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

_SS1_KEYWORDS = {
    "x25519", "X25519", "ecdh", "ECDH", "curve25519", "Curve25519",
    "ecc", "sntrup", "classical", "dh_shared",
}

_SS2_KEYWORDS = {
    "mlkem", "MLKEM", "kyber", "Kyber", "kem_secret", "pqc",
    "kem_shared", "kem_ss",
}


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


class S6FallbackChecker(BaseChecker):

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)

        if cpg.site.match_strategy not in ("direct", "colocation"):
            return []
        if not _HYBRID_FUNC_RE.search(cpg.site.function_name):
            return []

        findings: list[Finding] = []

        findings.extend(self._check_combiner_inputs(cpg, project))

        findings.extend(self._check_error_handlers(cpg, project))

        findings.extend(self._text_fallback_check(cpg, project))

        return findings


    def _check_combiner_inputs(self, cpg: FunctionCPG,
                                project: str) -> list[Finding]:
        findings: list[Finding] = []
        combiners = cpg.get_nodes_by_op(OpLabel.COMBINER)

        if not combiners:
            return findings

        cfg = nx.DiGraph()
        for n in cpg.nodes.values():
            cfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type.startswith("cfg"):
                cfg.add_edge(e.src, e.dst)

        for cnode in combiners:
            pred_ids = cpg.get_dataflow_predecessors(cnode.id, max_depth=6)
            pred_texts = [cnode.text]
            for pid in pred_ids:
                pnode = cpg.nodes.get(pid)
                if pnode:
                    pred_texts.append(pnode.text)

            combined_text = " ".join(pred_texts)

            has_ss1 = (
                any(kw in combined_text for kw in _SS1_KEYWORDS)
                or any(cpg.nodes[pid].component == 1
                       for pid in pred_ids if pid in cpg.nodes)
                or any(cpg.nodes[pid].val_label == ValLabel.K_1
                       for pid in pred_ids if pid in cpg.nodes)
            )
            has_ss2 = (
                any(kw in combined_text for kw in _SS2_KEYWORDS)
                or any(cpg.nodes[pid].component == 2
                       for pid in pred_ids if pid in cpg.nodes)
                or any(cpg.nodes[pid].val_label == ValLabel.K_2
                       for pid in pred_ids if pid in cpg.nodes)
            )

            if has_ss1 and has_ss2:
                continue

            has_success_exit = False
            if cnode.id in cfg and EXIT_ID in cfg:
                try:
                    has_success_exit = nx.has_path(cfg, cnode.id, EXIT_ID)
                except nx.NetworkXError:
                    pass

            if not has_success_exit:
                continue

            missing = []
            if not has_ss1:
                missing.append("ss_1 (classical)")
            if not has_ss2:
                missing.append("ss_2 (PQC)")

            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S6-1",
                verdict=Verdict.FAIL, severity=Severity.HIGH,
                evidence=(
                    f"COMBINER at L{cnode.line} does not consume both "
                    f"component secrets. Missing: {', '.join(missing)}. "
                    f"Hybrid KEM degrades to single-component."
                ),
                lines=[cnode.line],
            ))

        return findings


    def _check_error_handlers(self, cpg: FunctionCPG,
                               project: str) -> list[Finding]:
        findings: list[Finding] = []

        pqc_ops = [n for n in cpg.nodes.values()
                   if n.component == 2
                   and n.op_label in (OpLabel.ENCAP, OpLabel.DECAP)
                   and "(" in n.text]
        if not pqc_ops:
            pqc_ops = [n for n in cpg.get_nodes_by_label(CryptoLabel.PQC_OP)
                       if "(" in n.text]
        if not pqc_ops:
            return findings

        pqc_max_line = max(n.line for n in pqc_ops)
        error_checks = [n for n in cpg.get_nodes_by_op(OpLabel.ERROR_CHECK)
                        if n.line >= pqc_max_line]

        for ec in error_checks:
            handler_texts = []
            for succ_id, etype in cpg.get_cfg_successors(ec.id):
                succ = cpg.nodes.get(succ_id)
                if succ:
                    handler_texts.append(succ.text)
                    for s2_id, _ in cpg.get_cfg_successors(succ_id):
                        s2 = cpg.nodes.get(s2_id)
                        if s2:
                            handler_texts.append(s2.text)

            combined = " ".join(handler_texts)
            if _ABORT_RE.search(combined):
                continue

            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S6-1",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"PQC error check at L{ec.line}: handler does not "
                    f"clearly abort. May continue with partial key material."
                ),
                lines=[ec.line],
            ))

        return findings


    def _text_fallback_check(self, cpg: FunctionCPG,
                              project: str) -> list[Finding]:
        body = cpg.site.body_text
        findings: list[Finding] = []

        fallback_pats = [
            (re.compile(
                r"(?:if|when).*(?:kem|pqc|mlkem|kyber).*fail.*"
                r"(?:use|return|fall\s*back).*(?:classical|ecdh|x25519)",
                re.IGNORECASE | re.DOTALL),
             "Explicit classical fallback on PQC failure"),
            (re.compile(
                r"(?:pqc|kem|mlkem)_?(?:optional|disabled|skip)",
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
