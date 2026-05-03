from __future__ import annotations

import re
import os

import networkx as nx

from hkemlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    CryptoLabel, Severity, Verdict,
)
from hkemlint.checkers.base import BaseChecker
from hkemlint.checkers.s4_encap_zeroize import (
    _build_cfg, _is_real_call, _get_ss_buffers,
    _zeroize_targets_buffer, _has_cleanup_before_exit,
    _check_cpp_raii, EXIT_ID, _PATH_CUTOFF,
    _HYBRID_FUNC_RE,
)


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


_reported: set[str] = set()


def reset_s5_dedup():
    _reported.clear()


class S5DecapZeroizeChecker(BaseChecker):

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)

        if cpg.site.match_strategy not in ("direct", "colocation"):
            return []
        if not _HYBRID_FUNC_RE.search(cpg.site.function_name):
            return []

        findings: list[Finding] = []

        findings.extend(self._rust_half_success(cpg, project))
        findings.extend(self._rust_no_zeroize(cpg, project))
        findings.extend(self._go_no_zeroize(cpg, project))

        decap_1 = [n for n in cpg.get_nodes_by_op(OpLabel.DECAP)
                   if n.component == 1 and _is_real_call(n)]
        decap_2 = [n for n in cpg.get_nodes_by_op(OpLabel.DECAP)
                   if n.component == 2 and _is_real_call(n)]

        if not decap_1:
            decap_1 = [n for n in cpg.nodes.values()
                       if n.label == CryptoLabel.CLASSICAL_OP
                       and _is_real_call(n)
                       and re.search(r"decap|Decap|derive|shared_secret",
                                     n.text, re.IGNORECASE)]
        if not decap_2:
            decap_2 = [n for n in cpg.nodes.values()
                       if n.label == CryptoLabel.PQC_OP
                       and _is_real_call(n)
                       and re.search(r"decap|Decap", n.text, re.IGNORECASE)]

        if not decap_1 and not decap_2:
            if re.search(r"decap|Decap", cpg.site.function_name, re.IGNORECASE):
                decap_1 = [n for n in cpg.nodes.values()
                           if n.label == CryptoLabel.CLASSICAL_OP
                           and _is_real_call(n)]
                decap_2 = [n for n in cpg.nodes.values()
                           if n.label == CryptoLabel.PQC_OP
                           and _is_real_call(n)]

        if decap_1 and decap_2:
            cfg = _build_cfg(cpg)
            findings.extend(self._check_s5_1(cpg, cfg, decap_1, decap_2, project))
            findings.extend(self._check_s5_2(cpg, cfg, decap_1, decap_2, project))

        return findings


    def _check_s5_1(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                     comp1: list[CPGNode], comp2: list[CPGNode],
                     project: str) -> list[Finding]:
        findings: list[Finding] = []
        comp1_ids = {n.id for n in comp1}
        ss_bufs = _get_ss_buffers(cpg, comp1_ids)
        if not ss_bufs:
            return findings

        pqc_max_line = max(n.line for n in comp2)
        error_checks = [n for n in cpg.get_nodes_by_op(OpLabel.ERROR_CHECK)
                        if n.line >= pqc_max_line]
        zeroize_nodes = cpg.get_nodes_by_op(OpLabel.ZEROIZE)
        zeroize_ids = {n.id for n in zeroize_nodes
                       if _zeroize_targets_buffer(n, ss_bufs)}

        if not error_checks:
            if not zeroize_nodes:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S5-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"No error check after DECAP_2 and no zeroize of "
                        f"K_1 buffers ({ss_bufs})."
                    ),
                    lines=[pqc_max_line],
                ))
            return findings

        uncovered = []
        cleanup_ids = set()
        for node in cpg.nodes.values():
            if node.id != -1 and re.search(r"\b(FreeAll|free_all|Cleanup)\b", node.text):
                for name in ss_bufs:
                    if name and len(name) > 1 and name in node.text:
                        cleanup_ids.add(node.id)

        all_cover = zeroize_ids | cleanup_ids

        for ec in error_checks:
            for succ_id, _ in cpg.get_cfg_successors(ec.id):
                if succ_id not in cfg or EXIT_ID not in cfg:
                    continue
                if not nx.has_path(cfg, succ_id, EXIT_ID):
                    continue
                try:
                    for path in nx.all_simple_paths(cfg, succ_id, EXIT_ID,
                                                     cutoff=_PATH_CUTOFF):
                        if not (all_cover & set(path)):
                            uncovered.append((ec, succ_id, path))
                            break
                except nx.NetworkXError:
                    continue

        if uncovered:
            has_deferred = _has_cleanup_before_exit(cpg, ss_bufs)
            has_raii = _check_cpp_raii(cpg)
            if has_deferred or has_raii:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S5-1",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"Error path at L{uncovered[0][0].line} lacks "
                        f"immediate zeroize; deferred cleanup may cover K_1."
                    ),
                    lines=[uncovered[0][0].line],
                ))
            else:
                dedup_key = f"{cpg.site.file_path}::decap::{','.join(sorted(ss_bufs))}"
                if dedup_key not in _reported:
                    _reported.add(dedup_key)
                    ec, target, path = uncovered[0]
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S5-1",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"DECAP_2 error at L{ec.line} → EXIT: "
                            f"K_1 ({ss_bufs}) not zeroized on error path."
                        ),
                        lines=[ec.line],
                    ))

        return findings


    def _check_s5_2(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                     comp1: list[CPGNode], comp2: list[CPGNode],
                     project: str) -> list[Finding]:
        from hkemlint.checkers.s4_encap_zeroize import (
            _get_ss_buffers, _zeroize_targets_buffer,
            _has_cleanup_before_exit, _check_cpp_raii,
            EXIT_ID, _PATH_CUTOFF,
        )

        findings: list[Finding] = []

        combiners = cpg.get_nodes_by_op(OpLabel.COMBINER)
        if not combiners:
            return self._check_s5_2_fallback(cpg, cfg, comp1, comp2, project)

        first_op = min(comp1 + comp2, key=lambda n: n.line)
        second_op = max(comp1 + comp2, key=lambda n: n.line)

        ss_bufs_1 = _get_ss_buffers(cpg, {n.id for n in comp1})
        ss_bufs_2 = _get_ss_buffers(cpg, {n.id for n in comp2})
        all_ss = ss_bufs_1 | ss_bufs_2
        if not all_ss:
            return findings

        zeroize_nodes = cpg.get_nodes_by_op(OpLabel.ZEROIZE)

        for cnode in combiners:
            reachable_from_1 = any(
                cnode.id in cfg and n.id in cfg and nx.has_path(cfg, n.id, cnode.id)
                for n in comp1 if n.id in cfg
            )
            reachable_from_2 = any(
                cnode.id in cfg and n.id in cfg and nx.has_path(cfg, n.id, cnode.id)
                for n in comp2 if n.id in cfg
            )
            if not (reachable_from_1 and reachable_from_2):
                continue

            consumed_bufs: set[str] = set()
            pred_ids = cpg.get_dataflow_predecessors(cnode.id, max_depth=6)
            for pid in pred_ids:
                pnode = cpg.nodes.get(pid)
                if pnode:
                    for buf in all_ss:
                        if buf and len(buf) > 1 and buf in pnode.text:
                            consumed_bufs.add(buf)
            for buf in all_ss:
                if buf and len(buf) > 1 and buf in cnode.text:
                    consumed_bufs.add(buf)
            if not consumed_bufs:
                consumed_bufs = all_ss

            zeroize_ids = {z.id for z in zeroize_nodes
                           if _zeroize_targets_buffer(z, consumed_bufs)}

            if cnode.id not in cfg or EXIT_ID not in cfg:
                continue
            if not nx.has_path(cfg, cnode.id, EXIT_ID):
                continue

            uncovered_bufs: set[str] = set()
            try:
                for path in nx.all_simple_paths(cfg, cnode.id, EXIT_ID,
                                                 cutoff=_PATH_CUTOFF):
                    if not (zeroize_ids & set(path)):
                        uncovered_bufs |= consumed_bufs
                        break
            except nx.NetworkXError:
                continue

            if uncovered_bufs:
                has_deferred = _has_cleanup_before_exit(cpg, uncovered_bufs)
                has_raii = _check_cpp_raii(cpg)
                if has_deferred or has_raii:
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S5-2",
                        verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                        evidence=(
                            f"COMBINER at L{cnode.line} → return: "
                            f"component secrets ({uncovered_bufs}) not "
                            f"immediately zeroized; deferred cleanup may cover."
                        ),
                        lines=[cnode.line],
                    ))
                else:
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S5-2",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"COMBINER at L{cnode.line} → return: "
                            f"component secrets ({uncovered_bufs}) not "
                            f"zeroized on any CFG path to exit."
                        ),
                        lines=[cnode.line],
                    ))
            else:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S5-2",
                    verdict=Verdict.PASS, severity=Severity.LOW,
                    evidence=(
                        f"COMBINER at L{cnode.line} → return: component "
                        f"secrets zeroized on all CFG paths."
                    ),
                    lines=[cnode.line],
                ))

        return findings

    def _check_s5_2_fallback(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                              comp1: list[CPGNode], comp2: list[CPGNode],
                              project: str) -> list[Finding]:
        findings: list[Finding] = []
        first_op = min(comp1 + comp2, key=lambda n: n.line)
        second_op = max(comp1 + comp2, key=lambda n: n.line)
        zeroize_nodes = cpg.get_nodes_by_op(OpLabel.ZEROIZE)

        between = [z for z in zeroize_nodes
                   if first_op.line < z.line < second_op.line]
        after = [z for z in zeroize_nodes if z.line > second_op.line]

        if between or after:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S5-2",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"No explicit COMBINER found; zeroize exists "
                    f"{'between' if between else 'after'} decap ops."
                ),
                lines=[first_op.line, second_op.line],
            ))
        else:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S5-2",
                verdict=Verdict.FAIL, severity=Severity.HIGH,
                evidence=(
                    f"No COMBINER and no zeroize between DECAP_1 "
                    f"(L{first_op.line}) and DECAP_2 (L{second_op.line}) "
                    f"or after."
                ),
                lines=[first_op.line, second_op.line],
            ))
        return findings


    def _rust_half_success(self, cpg: FunctionCPG,
                            project: str) -> list[Finding]:
        if cpg.site.language.value != "rust":
            return []
        body = cpg.site.body_text
        lines = body.split("\n")
        ops = []
        for i, line in enumerate(lines):
            if re.search(r"decapsulate\s*\(.*\)\s*\?", line, re.IGNORECASE):
                ops.append((i + cpg.site.start_line, line.strip()))
        if len(ops) < 2:
            return []

        idx1 = ops[0][0] - cpg.site.start_line
        idx2 = ops[1][0] - cpg.site.start_line
        between = "\n".join(lines[idx1:idx2])
        if re.search(r"xor_assign|extend_from_slice|push|append|copy_from_slice", between):
            if "Zeroize" not in body and "ZeroizeOnDrop" not in body:
                return [Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S5-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Rust: decap 1 at L{ops[0][0]} writes to buffer, "
                        f"decap 2 at L{ops[1][0]} may fail with '?'. "
                        f"Buffer lacks Zeroize."
                    ),
                    lines=[ops[0][0], ops[1][0]],
                )]
        return []

    def _rust_no_zeroize(self, cpg: FunctionCPG,
                          project: str) -> list[Finding]:
        if cpg.site.language.value != "rust":
            return []
        body = cpg.site.body_text
        if not re.search(r"decapsulate|Decapsulate", body):
            return []

        findings: list[Finding] = []
        has_zeroize = "zeroize" in body.lower()

        vec_secrets = re.findall(
            r"let\s+(?:mut\s+)?(\w*secret\w*)\s*(?::\s*Vec<u8>)?\s*=\s*Vec::(?:new|with_capacity)",
            body, re.IGNORECASE,
        )
        for var in vec_secrets:
            if f"{var}.zeroize()" not in body and not has_zeroize:
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if var in l and "Vec::" in l), 0)
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S5-2",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=f"Rust Vec '{var}' in decap context lacks Zeroize.",
                    lines=[line_no] if line_no else [],
                ))
        return findings

    def _go_no_zeroize(self, cpg: FunctionCPG,
                        project: str) -> list[Finding]:
        if cpg.site.language.value != "go":
            return []
        body = cpg.site.body_text
        findings: list[Finding] = []

        if "sharedSecrets" in body:
            lines = body.split("\n")
            ops = [(i, l) for i, l in enumerate(lines)
                   if re.search(r"\.Decapsulate\(", l)]
            errs = [(i, l) for i, l in enumerate(lines)
                    if re.search(r"if\s+err\s*!=\s*nil", l)]
            if len(ops) >= 2 and errs:
                has_bzero = "ExplicitBzero" in body
                has_cleanup = re.search(
                    r"for\s+.*range\s+sharedSecrets.*\{|ExplicitBzero.*sharedSecrets",
                    body)
                if not has_bzero and not has_cleanup:
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S5-1",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"{len(ops)} sequential decaps with error returns. "
                            f"If decap[1] fails, sharedSecrets[0] persists "
                            f"on Go heap."
                        ),
                    ))

        if ("shared_secret" in body or "sharedKey" in body):
            if "ExplicitBzero" not in body and "explicit_bzero" not in body:
                if re.search(r"Decapsulate|decapsulate", body):
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S5-2",
                        verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                        evidence=(
                            "Go decap function handles shared secrets without "
                            "explicit zeroing. GC non-deterministic."
                        ),
                    ))

        return findings
