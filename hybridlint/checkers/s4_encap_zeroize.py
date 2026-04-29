"""S4 — Undestroyed Intermediate Key Material (Encapsulation).

S4-1  Undestroyed Intermediate on Half-Success (Encaps)
      Graph query: Find ENCAP(comp=1) producing K_1, then ENCAP(comp=2).
      On error path from ENCAP_2 to EXIT → check if ZEROIZE(K_1) exists.

S4-2  Undestroyed Intermediate on Completion (Encaps)
      Graph query: After both ENCAP nodes and COMBINER(K), trace CFG
      to EXIT. Check if ZEROIZE(K_1) and ZEROIZE(K_2) on path.
"""
from __future__ import annotations

import re
import os
from collections import deque

import networkx as nx

from hybridlint.cpg.models import (
    CPGNode, Finding, FunctionCPG, OpLabel, ValLabel,
    CryptoLabel, Severity, Verdict,
)
from hybridlint.checkers.base import BaseChecker

EXIT_ID = -1
_PATH_CUTOFF = 25

_REAL_CALL_RE = re.compile(
    r"\b("
    r"kexc25519_keygen|X25519_keypair|X25519\(|"
    r"EVP_PKEY_derive|wc_ecc_shared_secret|wc_curve25519_shared_secret|"
    r"MLKEM768_encap|MLKEM1024_encap|"
    r"wc_KyberEncapsulate|OQS_KEM_encaps|"
    r"libcrux_ml_kem.*encapsulate|"
    r"Encapsulate\(|encapsulate\("
    r")"
)

_ABORT_RE = re.compile(
    r"\b(goto\s+\w+|return\s+(-?\d+|err|error|ret|NULL|false|FAILURE|"
    r"BAD_FUNC_ARG|MEMORY_E|WOLFSSL_FAILURE|SSH_ERR_|S2N_ERR_)|"
    r"abort\s*\(|exit\s*\(|panic\s*\()",
    re.IGNORECASE,
)

# Hybrid function indicators for filtering
_HYBRID_FUNC_RE = re.compile(
    r"(hybrid|Hybrid|HYBRID|pqc_hybrid|ProcessPqcHybrid|"
    r"mlkem768x25519|sntrup761x25519|X25519MLKEM|xwing|XWing|"
    r"KeyAgreeEcdhMlKem|EcdhMlKem|ecdh_mlkem|"
    r"HybridKeyExchange|hybridKeyExchange|"
    r"initialize_alice|initialize_bob|"
    r"request_ephemeral_peer|register_peer|"
    r"Encapsulate|encapsulate|"
    r"combiner|Combiner|SplitPRF|PairSplitPRF|"
    r"oqs_hyb_kem|oqs_evp_kem|"
    r"KeyAgree|SendKexDhReply|"
    r"key_share|use_key_share|"
    r"Generate|Encap|Accept|Finish)",
    re.IGNORECASE,
)


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


def _build_cfg(cpg: FunctionCPG) -> nx.DiGraph:
    G = nx.DiGraph()
    for n in cpg.nodes.values():
        G.add_node(n.id)
    if EXIT_ID not in G:
        G.add_node(EXIT_ID)
    for e in cpg.edges:
        if e.edge_type.startswith("cfg"):
            G.add_edge(e.src, e.dst, edge_type=e.edge_type)
    return G


def _is_real_call(node: CPGNode) -> bool:
    text = node.text
    stripped = text.strip()
    if node.kind == "declaration" and "(" not in text and "=" not in text:
        return False
    if re.search(r"\b(dump_digest|DEBUG_KEXECDH|printf|fprintf|WLOG|debug\s*\()\b", text):
        return False
    if stripped.startswith(("#ifdef", "#endif", "#if ")):
        return False
    if node.kind == "comment":
        return False
    return "(" in text or "=" in text or _REAL_CALL_RE.search(text)


def _get_ss_buffers(cpg: FunctionCPG, op_ids: set[int]) -> set[str]:
    """Find shared-secret buffer names written by ops via dataflow."""
    buf_names: set[str] = set()
    for e in cpg.edges:
        if e.edge_type == "dataflow" and e.src in op_ids:
            dst = cpg.nodes.get(e.dst)
            if dst and dst.val_label in (ValLabel.K_1, ValLabel.K_2, ValLabel.K):
                buf_names.add(dst.detail.strip() if dst.detail else dst.text.strip())
            elif dst and dst.label == CryptoLabel.SECRET_BUF:
                buf_names.add(dst.detail.strip() if dst.detail else dst.text.strip())
    if not buf_names:
        for op_id in op_ids:
            op = cpg.nodes.get(op_id)
            if op:
                m = re.search(r"(\w+)\s*=", op.text)
                if m:
                    buf_names.add(m.group(1))
                m = re.search(r"\w+\s*\(\s*\w+\s*,\s*(\w+)", op.text)
                if m:
                    buf_names.add(m.group(1))
    body = cpg.site.body_text
    if "preMasterSecret" in body:
        buf_names.add("preMasterSecret")
    return buf_names


def _zeroize_targets_buffer(znode: CPGNode, buf_names: set[str]) -> bool:
    text = znode.text + " " + (znode.detail or "")
    for name in buf_names:
        if name and len(name) > 1 and name in text:
            return True
    return False


def _has_cleanup_before_exit(cpg: FunctionCPG, ss_bufs: set[str]) -> bool:
    cleanup_re = re.compile(
        r"\b(FreeAll|free_all|cleanup|Cleanup|_free_key_datum|"
        r"ForceZero|OPENSSL_cleanse|explicit_bzero|"
        r"zeroize|Zeroize|defer\s+.*zero|defer\s+.*clean)\b"
    )
    for node in cpg.nodes.values():
        if node.id == -1:
            continue
        if cleanup_re.search(node.text):
            for name in ss_bufs:
                if name and len(name) > 1 and name in node.text:
                    return True
    return False


def _check_cpp_raii(cpg: FunctionCPG) -> bool:
    if cpg.site.language.value not in ("cpp", "c"):
        return False
    src_dir = os.path.dirname(cpg.site.file_path)
    try:
        for fname in os.listdir(src_dir):
            if fname.endswith(('.h', '.hpp', '.hh', '.inc')):
                fpath = os.path.join(src_dir, fname)
                try:
                    with open(fpath, 'r', errors='replace') as f:
                        header = f.read()
                    if re.search(r"~\w+.*\{[^}]*OPENSSL_cleanse[^}]*\}", header, re.DOTALL):
                        return True
                except OSError:
                    pass
    except OSError:
        pass
    return False


# Track reported class members to avoid duplicates
_reported: set[str] = set()


def reset_s4_dedup():
    _reported.clear()


class S4EncapZeroizeChecker(BaseChecker):
    """S4-1 + S4-2: Undestroyed intermediate key material during encapsulation."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)

        if cpg.site.match_strategy not in ("direct", "colocation"):
            return []
        if not _HYBRID_FUNC_RE.search(cpg.site.function_name):
            return []

        findings: list[Finding] = []

        # Language-specific text checks
        findings.extend(self._rust_half_success(cpg, project, "encap"))
        findings.extend(self._rust_no_zeroize(cpg, project, "encap"))
        findings.extend(self._go_no_zeroize(cpg, project, "encap"))
        findings.extend(self._free_mismatch(cpg, project))

        # Graph-based: need both classical and PQC encap nodes
        encap_1 = [n for n in cpg.get_nodes_by_op(OpLabel.ENCAP)
                   if n.component == 1 and _is_real_call(n)]
        encap_2 = [n for n in cpg.get_nodes_by_op(OpLabel.ENCAP)
                   if n.component == 2 and _is_real_call(n)]

        # Also accept generic CLASSICAL_OP / PQC_OP that are encap-like
        if not encap_1:
            encap_1 = [n for n in cpg.nodes.values()
                       if n.label == CryptoLabel.CLASSICAL_OP
                       and _is_real_call(n)
                       and not re.search(r"decap|Decap", n.text, re.IGNORECASE)]
        if not encap_2:
            encap_2 = [n for n in cpg.nodes.values()
                       if n.label == CryptoLabel.PQC_OP
                       and _is_real_call(n)
                       and not re.search(r"decap|Decap", n.text, re.IGNORECASE)]

        if encap_1 and encap_2:
            cfg = _build_cfg(cpg)
            findings.extend(self._check_s4_1(cpg, cfg, encap_1, encap_2, project))
            findings.extend(self._check_s4_2(cpg, cfg, encap_1, encap_2, project))

        return findings

    # ── S4-1: Half-success (encaps) ─────────────────────────────────

    def _check_s4_1(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                     comp1: list[CPGNode], comp2: list[CPGNode],
                     project: str) -> list[Finding]:
        """After ENCAP_1 succeeds and ENCAP_2 fails, is K_1 zeroized?"""
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
                    rule_id="S4-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"No error check after ENCAP_2 and no zeroize of "
                        f"K_1 buffers ({ss_bufs})."
                    ),
                    lines=[pqc_max_line],
                ))
            return findings

        # Trace error paths to EXIT
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
                    rule_id="S4-1",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"Error path at L{uncovered[0][0].line} lacks "
                        f"immediate zeroize; deferred cleanup may cover K_1."
                    ),
                    lines=[uncovered[0][0].line],
                ))
            else:
                dedup_key = f"{cpg.site.file_path}::encap::{','.join(sorted(ss_bufs))}"
                if dedup_key not in _reported:
                    _reported.add(dedup_key)
                    ec, target, path = uncovered[0]
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S4-1",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"ENCAP_2 error at L{ec.line} → EXIT: "
                            f"K_1 ({ss_bufs}) not zeroized on error path."
                        ),
                        lines=[ec.line],
                    ))

        return findings

    # ── S4-2: Completion (encaps) ───────────────────────────────────

    def _check_s4_2(self, cpg: FunctionCPG, cfg: nx.DiGraph,
                     comp1: list[CPGNode], comp2: list[CPGNode],
                     project: str) -> list[Finding]:
        """After both encaps succeed, are K_1/K_2 zeroized before exit?"""
        findings: list[Finding] = []
        first_op = min(comp1 + comp2, key=lambda n: n.line)
        second_op = max(comp1 + comp2, key=lambda n: n.line)

        zeroize_nodes = cpg.get_nodes_by_op(OpLabel.ZEROIZE)

        between = [z for z in zeroize_nodes
                   if first_op.line < z.line < second_op.line]
        after = [z for z in zeroize_nodes if z.line > second_op.line]

        if between:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S4-2",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=(
                    f"Intermediate key zeroized between ENCAP_1 "
                    f"(L{first_op.line}) and ENCAP_2 (L{second_op.line})."
                ),
            ))
        elif after:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S4-2",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"Intermediate key persists between encaps "
                    f"(L{first_op.line}—L{second_op.line}); "
                    f"cleanup at L{after[0].line}."
                ),
                lines=[first_op.line, second_op.line, after[0].line],
            ))
        else:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                rule_id="S4-2",
                verdict=Verdict.FAIL, severity=Severity.HIGH,
                evidence=(
                    f"No zeroize of intermediate key between ENCAP_1 "
                    f"(L{first_op.line}) and ENCAP_2 (L{second_op.line}) "
                    f"or after."
                ),
                lines=[first_op.line, second_op.line],
            ))

        return findings

    # ── Language-specific helpers ────────────────────────────────────

    def _rust_half_success(self, cpg: FunctionCPG, project: str,
                            ctx: str) -> list[Finding]:
        if cpg.site.language.value != "rust":
            return []
        body = cpg.site.body_text
        lines = body.split("\n")
        ops = []
        for i, line in enumerate(lines):
            if re.search(r"encapsulate\s*\(.*\)\s*\?", line, re.IGNORECASE):
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
                    rule_id="S4-1",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Rust: encap 1 at L{ops[0][0]} writes to buffer, "
                        f"encap 2 at L{ops[1][0]} may fail with '?'. "
                        f"Buffer lacks Zeroize."
                    ),
                    lines=[ops[0][0], ops[1][0]],
                )]
        return []

    def _rust_no_zeroize(self, cpg: FunctionCPG, project: str,
                          ctx: str) -> list[Finding]:
        if cpg.site.language.value != "rust":
            return []
        body = cpg.site.body_text
        findings: list[Finding] = []
        has_zeroize = "zeroize" in body.lower()

        # Vec<u8> accumulating secrets
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
                    rule_id="S4-2",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=f"Rust Vec '{var}' holds secrets without Zeroize.",
                    lines=[line_no] if line_no else [],
                ))

        # extend_from_slice accumulating DH/KEM outputs
        if re.search(r"extend_from_slice.*(?:dh|ecdh|kem|shared|agreement)", body, re.IGNORECASE):
            if not has_zeroize:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    rule_id="S4-2",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence="Accumulates DH/KEM secrets via extend_from_slice without zeroize.",
                ))

        # Structs without Zeroize
        findings.extend(self._rust_struct_no_zeroize(cpg, project, "S4-2"))
        return findings

    def _rust_struct_no_zeroize(self, cpg: FunctionCPG, project: str,
                                 rule_id: str) -> list[Finding]:
        if cpg.site.language.value != "rust":
            return []
        findings: list[Finding] = []
        file_texts = []
        try:
            with open(cpg.site.file_path, "r", errors="replace") as f:
                file_texts.append((cpg.site.file_path, f.read()))
            src_dir = os.path.dirname(cpg.site.file_path)
            for fname in os.listdir(src_dir):
                if fname.endswith(".rs") and fname != os.path.basename(cpg.site.file_path):
                    fpath = os.path.join(src_dir, fname)
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            file_texts.append((fpath, f.read()))
                    except OSError:
                        pass
        except OSError:
            return findings

        struct_pat = re.compile(
            r"pub\s+struct\s+(\w*(?:Keypair|PrivateKey|SecretKey|SharedSecret|"
            r"KeyPair|DecapsulationKey|Secret)\w*)\s*[\{(]",
            re.IGNORECASE,
        )
        for path, text in file_texts:
            for m in struct_pat.finditer(text):
                name = m.group(1)
                has_z = bool(re.search(
                    rf"(#\[derive\(.*Zeroize.*\)\].*struct\s+{re.escape(name)}|"
                    rf"impl\s+(?:Drop|Zeroize|ZeroizeOnDrop)\s+for\s+{re.escape(name)})",
                    text, re.DOTALL,
                ))
                if not has_z:
                    line_no = text[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        project=project,
                        file_path=path,
                        function_name=name,
                        rule_id=rule_id,
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=f"Struct '{name}' holds key material without Zeroize/Drop.",
                        lines=[line_no],
                    ))
        return findings

    def _go_no_zeroize(self, cpg: FunctionCPG, project: str,
                        ctx: str) -> list[Finding]:
        if cpg.site.language.value != "go":
            return []
        body = cpg.site.body_text
        findings: list[Finding] = []

        if "sharedSecrets" in body:
            lines = body.split("\n")
            ops = [(i, l) for i, l in enumerate(lines)
                   if re.search(r"\.Encapsulate\(", l)]
            errs = [(i, l) for i, l in enumerate(lines)
                    if re.search(r"if\s+err\s*!=\s*nil", l)]
            if len(ops) >= 2 and errs:
                has_bzero = "ExplicitBzero" in body
                has_cleanup = re.search(
                    r"for\s+.*range\s+sharedSecrets.*\{|ExplicitBzero.*sharedSecrets", body)
                if not has_bzero and not has_cleanup:
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        rule_id="S4-1",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"{len(ops)} sequential encaps with error returns. "
                            f"If encap[1] fails, sharedSecrets[0] persists."
                        ),
                    ))

        return findings

    def _free_mismatch(self, cpg: FunctionCPG, project: str) -> list[Finding]:
        """GnuTLS: insecure free of secret buffer."""
        findings: list[Finding] = []
        for node in cpg.nodes.values():
            if node.label == CryptoLabel.FREE_NO_ZERO:
                if "_gnutls_free_datum" in node.text:
                    _BUF_PAT = re.compile(
                        r"\b\w*(secret|key|shared|ss|pms|datum)\w*\b", re.IGNORECASE)
                    if _BUF_PAT.search(node.text):
                        findings.append(Finding(
                            project=project,
                            file_path=cpg.site.file_path,
                            function_name=cpg.site.function_name,
                            rule_id="S4-1",
                            verdict=Verdict.FAIL, severity=Severity.HIGH,
                            evidence=(
                                f"Insecure _gnutls_free_datum at L{node.line} "
                                f"frees key material without zeroizing."
                            ),
                            lines=[node.line],
                        ))
        return findings
