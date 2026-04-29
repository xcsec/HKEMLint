"""SP2 -- Operation Atomicity checker.

Uses the CPG (CFG edges + dataflow edges + node labels) to perform
real graph-based path analysis:

  SP2a: For each error path after PQC op, trace CFG to EXIT and check
        if a ZEROIZE node targeting the classical SS is on the path.
  SP2b: Check if error handlers abort (goto err/return error) vs
        silently continuing.
  SP2c: Check if intermediate key material persists between the two ops.
"""
from __future__ import annotations

import re
from collections import deque

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
_PATH_CUTOFF = 25

# Known crypto call patterns (not declarations or debug prints)
_REAL_CALL_RE = re.compile(
    r"\b("
    # Classical
    r"kexc25519_keygen|X25519_keypair|X25519\(|X25519_public_from_private|"
    r"EVP_PKEY_derive|EVP_PKEY_keygen|wc_ecc_shared_secret|"
    r"wc_curve25519_shared_secret|kexc25519_shared_key_ext|"
    r"crypto_scalarmult_curve25519|"
    r"TLSX_KeyShare_ProcessEcc_ex|TLSX_KeyShare_ProcessX25519_ex|"
    r"ecdh\.ECDH|curve\.GenerateKey|ECDH_compute_key|"
    # PQC
    r"MLKEM768_encap|MLKEM768_decap|MLKEM1024_encap|MLKEM1024_decap|"
    r"MLKEM768_generate_key|MLKEM1024_generate_key|"
    r"libcrux_ml_kem.*encapsulate|libcrux_ml_kem.*decapsulate|"
    r"libcrux_ml_kem.*generate_key_pair|"
    r"wc_KyberEncapsulate|wc_KyberDecapsulate|wc_KyberKey_MakeKey|"
    r"OQS_KEM_encaps|OQS_KEM_decaps|OQS_KEM_keypair|"
    r"TLSX_KeyShare_ProcessPqcClient_ex|"
    r"crypto_kem_sntrup761_enc|crypto_kem_sntrup761_dec|"
    r"Encapsulate\(|Decapsulate\(|encapsulate\(|decapsulate\("
    r")"
)

# Abort patterns in error handlers
_ABORT_RE = re.compile(
    r"\b(goto\s+\w+|return\s+(-?\d+|err|error|ret|NULL|false|FAILURE|"
    r"BAD_FUNC_ARG|MEMORY_E|WOLFSSL_FAILURE|SSH_ERR_|S2N_ERR_)|"
    r"abort\s*\(|exit\s*\(|panic\s*\()",
    re.IGNORECASE,
)


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


def _is_real_call(node: CPGNode) -> bool:
    """Is this node an actual crypto operation (not a pure declaration/debug/preprocessor)?

    We trust the labeler's CLASSICAL_OP/PQC_OP assignment, but filter out
    obvious non-operations: bare declarations without function calls,
    debug/logging statements, and preprocessor directives.
    """
    text = node.text
    stripped = text.strip()
    # Pure declaration without function call or assignment
    if node.kind == "declaration" and "(" not in text and "=" not in text:
        return False
    # Debug/logging
    if re.search(r"\b(dump_digest|DEBUG_KEXECDH|printf|fprintf|WLOG|WOLFSSL_MSG|debug\s*\()\b", text):
        return False
    # Preprocessor
    if stripped.startswith("#ifdef") or stripped.startswith("#endif") or stripped.startswith("#if "):
        return False
    # Comment
    if node.kind == "comment":
        return False
    # Must have a function call pattern OR an assignment OR a known operation
    if "(" in text or "=" in text or _REAL_CALL_RE.search(text):
        return True
    return False


def _build_cfg(cpg: FunctionCPG) -> nx.DiGraph:
    """Build a NetworkX digraph from CFG edges only."""
    G = nx.DiGraph()
    for n in cpg.nodes.values():
        G.add_node(n.id)
    if EXIT_ID not in G:
        G.add_node(EXIT_ID)
    for e in cpg.edges:
        if e.edge_type.startswith("cfg"):
            G.add_edge(e.src, e.dst, edge_type=e.edge_type)
    return G


def _get_ss_buffers_from_dataflow(cpg: FunctionCPG,
                                   op_ids: set[int]) -> set[str]:
    """Find secret buffer names written by ops, using dataflow edges."""
    buf_names = set()
    for e in cpg.edges:
        if e.edge_type == "dataflow" and e.src in op_ids:
            dst = cpg.nodes.get(e.dst)
            if dst and dst.label == CryptoLabel.SECRET_BUF:
                buf_names.add(dst.detail.strip() if dst.detail else dst.text.strip())
    # Fallback: if no dataflow edges found, use heuristic from op text
    if not buf_names:
        for op_id in op_ids:
            op = cpg.nodes.get(op_id)
            if op:
                # Look for assignment LHS or first arg of function call
                m = re.search(r"(\w+)\s*=", op.text)
                if m:
                    buf_names.add(m.group(1))
                m = re.search(r"\w+\s*\(\s*\w+\s*,\s*(\w+)", op.text)
                if m:
                    buf_names.add(m.group(1))
    # Also always track preMasterSecret (wolfSSL's main buffer)
    body = cpg.site.body_text
    if "preMasterSecret" in body:
        buf_names.add("preMasterSecret")
    return buf_names


def _zeroize_targets_buffer(znode: CPGNode, buf_names: set[str]) -> bool:
    """Does this ZEROIZE node target any of the named buffers?"""
    text = znode.text + " " + (znode.detail or "")
    for name in buf_names:
        if name and len(name) > 1 and name in text:
            return True
    return False


def _has_cleanup_before_exit(cpg: FunctionCPG, cfg, ss_bufs: set[str]) -> bool:
    """Check if there's a cleanup/FreeAll/destructor call that covers SS buffers
    anywhere reachable before EXIT — not just on the direct error path.

    This catches:
    - wolfSSL's TLSX_KeyShare_FreeAll() pattern (deferred cleanup)
    - C++ RAII destructors that trigger on scope exit
    - Go defer statements
    """
    # Look for cleanup-like nodes anywhere in the function
    cleanup_patterns = re.compile(
        r"\b(FreeAll|free_all|cleanup|Cleanup|_free_key_datum|"
        r"ForceZero|OPENSSL_cleanse|explicit_bzero|"
        r"zeroize|Zeroize|defer\s+.*zero|defer\s+.*clean)\b"
    )
    for node in cpg.nodes.values():
        if node.id == -1:
            continue
        if cleanup_patterns.search(node.text):
            # Check if this cleanup targets any of our SS buffers
            for name in ss_bufs:
                if name and len(name) > 1 and name in node.text:
                    return True
    return False


def _check_cpp_raii_zeroize(cpg: FunctionCPG) -> bool:
    """Check if C++ class types used for secret buffers have destructors
    that call OPENSSL_cleanse or equivalent.

    Reads the source file and sibling headers to find class definitions.
    """
    if cpg.site.language.value not in ("cpp", "c"):
        return False

    import os
    # Find header files in the same directory
    src_dir = os.path.dirname(cpg.site.file_path)
    header_texts = []
    try:
        for fname in os.listdir(src_dir):
            if fname.endswith(('.h', '.hpp', '.hh', '.inc')):
                fpath = os.path.join(src_dir, fname)
                try:
                    with open(fpath, 'r', errors='replace') as f:
                        header_texts.append(f.read())
                except OSError:
                    pass
    except OSError:
        pass

    # Check if Array<> or similar types have cleanse in destructor
    for header in header_texts:
        # Look for destructor that calls cleanse
        if re.search(r"~\w+.*\{[^}]*OPENSSL_cleanse[^}]*\}", header, re.DOTALL):
            return True
        # Look for Reset() that calls cleanse before free
        if re.search(r"Reset\s*\([^)]*\)[^{]*\{[^}]*OPENSSL_cleanse[^}]*OPENSSL_free", header, re.DOTALL):
            return True
    return False


# Track already-reported class members to avoid duplicates (reset per scan)
_reported_class_members: set[str] = set()


def reset_sp2_dedup():
    """Call between projects to reset deduplication state."""
    _reported_class_members.clear()


class SP2AtomicityChecker(BaseChecker):
    """SP2: Check operation atomicity using CPG graph queries."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        project = _project_name(cpg.site.file_path)

        # SP2 (S4/S5) only applies to functions with two-step hybrid KEM operations.
        # Skip: config sites, struct definitions, non-hybrid utility functions.
        if cpg.site.match_strategy not in ("direct", "colocation"):
            return []

        # Additional filter: reduce FP by requiring the function to be
        # a genuine hybrid KEM operation function, not a utility that
        # happens to mention both classical and PQC keywords.
        # Heuristic: function name or body must contain hybrid-specific identifiers.
        _HYBRID_FUNC_INDICATORS = re.compile(
            r"(hybrid|Hybrid|HYBRID|pqc_hybrid|ProcessPqcHybrid|HandlePqcHybrid|"
            r"mlkem768x25519|sntrup761x25519|X25519MLKEM|xwing|XWing|"
            r"KeyAgreeEcdhMlKem|EcdhMlKem|ecdh_mlkem|"
            r"HybridKeyExchange|hybridKeyExchange|"
            r"initialize_alice|initialize_bob|"  # Signal PQXDH
            r"request_ephemeral_peer|register_peer|"  # Mullvad
            r"Encapsulate|Decapsulate|encapsulate|decapsulate|"
            r"combiner|Combiner|SplitPRF|PairSplitPRF|"
            r"oqs_hyb_kem|oqs_evp_kem|"
            r"KeyAgree|SendKexDhReply|"  # wolfSSH
            r"key_share|use_key_share|"  # GnuTLS
            r"Generate|Encap|Decap|Accept|Finish)",  # BoringSSL/AWS-LC class methods
            re.IGNORECASE
        )
        func_name = cpg.site.function_name
        # Only run S4/S5 checks on functions whose name indicates hybrid KEM operation
        if not _HYBRID_FUNC_INDICATORS.search(func_name):
            return []

        # Text-based checks (only for functions with real crypto operations)
        findings = []
        findings.extend(self._sp2_free_mismatch(cpg, project))
        findings.extend(self._sp2_rust_half_success(cpg, project))
        findings.extend(self._sp2_rust_no_zeroize(cpg, project))
        findings.extend(self._sp2_rust_struct_no_zeroize(cpg, project))
        findings.extend(self._sp2_go_no_zeroize(cpg, project))

        # Graph-based checks require both classical and PQC call nodes
        classical = [n for n in cpg.get_nodes_by_label(CryptoLabel.CLASSICAL_OP)
                     if _is_real_call(n)]
        pqc = [n for n in cpg.get_nodes_by_label(CryptoLabel.PQC_OP)
               if _is_real_call(n)]

        if classical and pqc:
            cfg = _build_cfg(cpg)
            findings.extend(self._sp2a(cpg, cfg, classical, pqc, project))
            findings.extend(self._sp2b(cpg, cfg, pqc, project))
            findings.extend(self._sp2c(cpg, cfg, classical, pqc, project))

        return findings

    # ── SP2a: error-path zeroize coverage ────────────────────────

    def _sp2a(self, cpg: FunctionCPG, cfg: nx.DiGraph,
              classical: list[CPGNode], pqc: list[CPGNode],
              project: str) -> list[Finding]:
        """
        Core graph query:
          1. Find classical_op that writes to SS buffer
          2. Find error_check nodes AFTER the last pqc_op
          3. From each error_check, follow CFG edges to EXIT
          4. On each path, check if a ZEROIZE node targets the SS buffer
        """
        findings = []
        classical_ids = {n.id for n in classical}
        ss_bufs = _get_ss_buffers_from_dataflow(cpg, classical_ids)

        if not ss_bufs:
            return findings

        pqc_max_line = max(n.line for n in pqc)
        error_checks = [n for n in cpg.get_nodes_by_label(CryptoLabel.ERROR_CHECK)
                        if n.line >= pqc_max_line]
        zeroize_nodes = cpg.get_nodes_by_label(CryptoLabel.ZEROIZE)
        zeroize_ids = {n.id for n in zeroize_nodes
                       if _zeroize_targets_buffer(n, ss_bufs)}

        if not error_checks:
            # No error check after PQC op — check if function has any cleanup
            if not zeroize_nodes:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"No error check after PQC ops and no zeroize of "
                        f"classical SS buffers ({ss_bufs}) anywhere in function."
                    ),
                    lines=[pqc_max_line],
                ))
            else:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"No error check after PQC op at L{pqc_max_line}. "
                        f"Zeroize exists but coverage not verified."
                    ),
                    lines=[pqc_max_line],
                ))
            return findings

        # For each error check, trace CFG paths to EXIT
        uncovered_paths = []
        for ec in error_checks:
            # Find the error-handling branch targets
            targets = []
            for succ, etype in cpg.get_cfg_successors(ec.id):
                targets.append(succ)

            for target in targets:
                if target not in cfg or EXIT_ID not in cfg:
                    continue
                if not nx.has_path(cfg, target, EXIT_ID):
                    continue

                # Check ALL simple paths from error target to EXIT
                # Also consider: nodes labeled FREE_NO_ZERO that call FreeAll/cleanup
                cleanup_ids = set()
                for node in cpg.nodes.values():
                    if node.id == -1:
                        continue
                    if re.search(r"\b(FreeAll|free_all|Cleanup|cleanup)\b", node.text):
                        for name in ss_bufs:
                            if name and len(name) > 1 and name in node.text:
                                cleanup_ids.add(node.id)

                all_cover_ids = zeroize_ids | cleanup_ids

                try:
                    has_zeroize_on_all = True
                    for path in nx.all_simple_paths(cfg, target, EXIT_ID,
                                                     cutoff=_PATH_CUTOFF):
                        path_has_zeroize = bool(all_cover_ids & set(path))
                        if not path_has_zeroize:
                            has_zeroize_on_all = False
                            uncovered_paths.append((ec, target, path))
                            break  # one uncovered path is enough
                except nx.NetworkXError:
                    continue

        if uncovered_paths:
            # Before reporting: check for deferred cleanup or RAII
            has_deferred = _has_cleanup_before_exit(cpg, cfg, ss_bufs)
            has_raii = _check_cpp_raii_zeroize(cpg)

            if has_deferred or has_raii:
                # Deferred cleanup exists — downgrade to UNCERTAIN
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"Error path at L{uncovered_paths[0][0].line} lacks "
                        f"immediate zeroize, but deferred cleanup "
                        f"({'RAII destructor' if has_raii else 'FreeAll/cleanup'}) "
                        f"may cover SS ({ss_bufs})."
                    ),
                    lines=[uncovered_paths[0][0].line],
                ))
            else:
                # Dedup: skip if same class member already reported
                dedup_key = f"{cpg.site.file_path}::{','.join(sorted(ss_bufs))}"
                if dedup_key in _reported_class_members:
                    pass  # skip duplicate
                else:
                    _reported_class_members.add(dedup_key)
                    ec, target, path = uncovered_paths[0]
                    findings.append(Finding(
                        project=project,
                        file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        sp="SP2", sub_property="SP2a",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"Error check at L{ec.line} → handler at node {target} "
                            f"→ EXIT: path has NO zeroize of classical SS ({ss_bufs}). "
                            f"Path length: {len(path)} nodes."
                        ),
                        lines=[ec.line] + [cpg.nodes[n].line for n in path[:3]
                                            if n in cpg.nodes and n != EXIT_ID],
                    ))
        else:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP2", sub_property="SP2a",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=(
                    f"All error paths after PQC ops zeroize classical SS "
                    f"({ss_bufs}) before exit."
                ),
            ))

        return findings

    # ── SP2b: error handlers abort ───────────────────────────────

    def _sp2b(self, cpg: FunctionCPG, cfg: nx.DiGraph,
              pqc: list[CPGNode], project: str) -> list[Finding]:
        """Check if error handlers abort rather than silently continuing."""
        findings = []
        pqc_max_line = max(n.line for n in pqc)
        error_checks = [n for n in cpg.get_nodes_by_label(CryptoLabel.ERROR_CHECK)
                        if n.line >= pqc_max_line]

        if not error_checks:
            return findings

        for ec in error_checks:
            # Collect text from error handler branch (cfg successors)
            handler_texts = []
            for succ_id, etype in cpg.get_cfg_successors(ec.id):
                succ = cpg.nodes.get(succ_id)
                if succ:
                    handler_texts.append(succ.text)
                    # Also check the next hop
                    for succ2_id, _ in cpg.get_cfg_successors(succ_id):
                        s2 = cpg.nodes.get(succ2_id)
                        if s2:
                            handler_texts.append(s2.text)

            combined = " ".join(handler_texts)
            if _ABORT_RE.search(combined):
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2b",
                    verdict=Verdict.PASS, severity=Severity.LOW,
                    evidence=f"Error handler at L{ec.line} aborts on PQC failure.",
                    lines=[ec.line],
                ))
            else:
                findings.append(Finding(
                    project=project,
                    file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2b",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"Error handler at L{ec.line}: cannot confirm abort. "
                        f"May silently continue with classical-only SS."
                    ),
                    lines=[ec.line],
                ))

        return findings

    # ── SP2c: intermediate key material between ops ──────────────

    def _sp2c(self, cpg: FunctionCPG, cfg: nx.DiGraph,
              classical: list[CPGNode], pqc: list[CPGNode],
              project: str) -> list[Finding]:
        """Check if classical ephemeral key persists between the two ops."""
        findings = []
        first_op = min(classical + pqc, key=lambda n: n.line)
        second_op = max(classical + pqc, key=lambda n: n.line)

        # The first op's output — does it get zeroized before function exit?
        zeroize_nodes = cpg.get_nodes_by_label(CryptoLabel.ZEROIZE)

        # Check if any zeroize happens between the two ops
        between_zeroize = [z for z in zeroize_nodes
                           if first_op.line < z.line < second_op.line]

        # Check if any zeroize happens after both ops (cleanup section)
        after_zeroize = [z for z in zeroize_nodes
                         if z.line > second_op.line]

        if between_zeroize:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP2", sub_property="SP2c",
                verdict=Verdict.PASS, severity=Severity.LOW,
                evidence=(
                    f"Intermediate key material zeroized between op1 (L{first_op.line}) "
                    f"and op2 (L{second_op.line})."
                ),
            ))
        elif after_zeroize:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP2", sub_property="SP2c",
                verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                evidence=(
                    f"Intermediate key material persists between op1 (L{first_op.line}) "
                    f"and op2 (L{second_op.line}); cleanup at L{after_zeroize[0].line}."
                ),
                lines=[first_op.line, second_op.line, after_zeroize[0].line],
            ))
        else:
            findings.append(Finding(
                project=project,
                file_path=cpg.site.file_path,
                function_name=cpg.site.function_name,
                sp="SP2", sub_property="SP2c",
                verdict=Verdict.FAIL, severity=Severity.HIGH,
                evidence=(
                    f"No zeroize found for intermediate key material between "
                    f"op1 (L{first_op.line}) and op2 (L{second_op.line}) "
                    f"or after. Key material may persist in memory."
                ),
                lines=[first_op.line, second_op.line],
            ))

        return findings

    # ── SP2 GnuTLS: secure-free vs plain-free mismatch ──────────

    def _sp2_free_mismatch(self, cpg: FunctionCPG,
                            project: str) -> list[Finding]:
        """Detect GnuTLS B3: shared secret freed with insecure free."""
        findings = []
        free_nodes = cpg.get_nodes_by_label(CryptoLabel.FREE_NO_ZERO)
        secret_bufs = cpg.get_nodes_by_label(CryptoLabel.SECRET_BUF)
        buf_names = {n.detail.strip() for n in secret_bufs if n.detail}
        _BUF_PAT = re.compile(
            r"\b\w*(secret|key|shared|ss|pms|preMaster|datum)\w*\b", re.IGNORECASE)

        for fn in free_nodes:
            text = fn.text
            is_secret = (any(name in text for name in buf_names if name)
                         or _BUF_PAT.search(text))
            if not is_secret:
                continue
            if "_gnutls_free_datum" in text:
                findings.append(Finding(
                    project=project, file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(f"Insecure _gnutls_free_datum at L{fn.line} frees key "
                              f"material without zeroizing. Use _gnutls_free_key_datum."),
                    lines=[fn.line]))
        return findings

    # ── SP2 Rust: ? operator half-success ────────────────────────

    def _sp2_rust_half_success(self, cpg: FunctionCPG,
                                project: str) -> list[Finding]:
        """Detect Rust half-success: two ? ops where first SS leaks on second failure."""
        findings = []
        body = cpg.site.body_text
        if cpg.site.language.value != "rust":
            return findings

        lines = body.split("\n")
        component_ops = []
        for i, line in enumerate(lines):
            if re.search(r"(decapsulate|encapsulate)\s*\(.*\)\s*\?", line, re.IGNORECASE):
                component_ops.append((i + cpg.site.start_line, line.strip()))

        if len(component_ops) < 2:
            return findings

        first_idx = component_ops[0][0] - cpg.site.start_line
        second_idx = component_ops[1][0] - cpg.site.start_line
        between = "\n".join(lines[first_idx:second_idx])

        if re.search(r"xor_assign|extend_from_slice|push|append|copy_from_slice", between):
            has_zeroize = "Zeroize" in body or "ZeroizeOnDrop" in body
            if not has_zeroize:
                findings.append(Finding(
                    project=project, file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Rust half-success: component 1 at L{component_ops[0][0]} "
                        f"writes to buffer, component 2 at L{component_ops[1][0]} "
                        f"may fail with '?'. Buffer lacks Zeroize."),
                    lines=[component_ops[0][0], component_ops[1][0]]))
        return findings

    # ── SP2 Rust: secret types without Zeroize trait ─────────────

    def _sp2_rust_no_zeroize(self, cpg: FunctionCPG,
                              project: str) -> list[Finding]:
        """Detect Rust secret buffers stored in types without Zeroize.
        Covers: Signal A3/B7, Mullvad B6, rustls E9.

        Patterns:
        - Vec<u8> holding secrets (Signal: secrets = Vec::with_capacity)
        - Box<[u8]> or Box<[u8; N]> holding secrets without ZeroizeOnDrop
        - Types deriving Copy for private keys (Signal: PrivateKey derives Copy)
        """
        findings = []
        body = cpg.site.body_text
        if cpg.site.language.value != "rust":
            return findings

        has_zeroize_import = "zeroize" in body.lower()

        # Pattern 1: Vec<u8> accumulating secrets
        # Signal PQXDH: let mut secrets = Vec::with_capacity(32 * 6);
        vec_secrets = re.findall(
            r"let\s+(?:mut\s+)?(\w*secret\w*)\s*(?::\s*Vec<u8>)?\s*=\s*Vec::(?:new|with_capacity)",
            body, re.IGNORECASE
        )
        for var_name in vec_secrets:
            # Check if .zeroize() is called on this variable
            if f"{var_name}.zeroize()" not in body and not has_zeroize_import:
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if var_name in l and "Vec::" in l), 0
                )
                findings.append(Finding(
                    project=project, file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Rust Vec<u8> '{var_name}' accumulates secret key material "
                        f"but is never zeroized (no .zeroize() call, no Zeroize import)."
                    ),
                    lines=[line_no] if line_no else [],
                ))

        # Pattern 2: Box<[u8; N]> without ZeroizeOnDrop
        box_secrets = re.findall(
            r"let\s+(?:mut\s+)?(\w*(?:psk|secret|key|ss)\w*)\s*(?::\s*Box<\[u8)?\s*=\s*Box::new\(\[0u8",
            body, re.IGNORECASE
        )
        for var_name in box_secrets:
            if "ZeroizeOnDrop" not in body and "Zeroizing<" not in body:
                line_no = next(
                    (i + cpg.site.start_line for i, l in enumerate(body.split("\n"))
                     if var_name in l and "Box::new" in l), 0
                )
                findings.append(Finding(
                    project=project, file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Rust Box '{var_name}' holds secret key material "
                        f"without ZeroizeOnDrop. Memory not zeroized on drop."
                    ),
                    lines=[line_no] if line_no else [],
                ))

        # Pattern 3: extend_from_slice accumulating DH/KEM outputs
        # Signal: secrets.extend_from_slice(&dh1); ... secrets.extend_from_slice(&kem_ss);
        if re.search(r"extend_from_slice.*(?:dh|ecdh|kem|shared|agreement)", body, re.IGNORECASE):
            if not has_zeroize_import:
                findings.append(Finding(
                    project=project, file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Function accumulates DH/KEM shared secrets via "
                        f"extend_from_slice but has no zeroize import. "
                        f"Accumulated key material not cleared on function exit."
                    ),
                ))

        return findings

    # ── SP2 Rust: struct definitions missing Zeroize ─────────────

    def _sp2_rust_struct_no_zeroize(self, cpg: FunctionCPG,
                                     project: str) -> list[Finding]:
        """Detect Rust structs holding key material without Zeroize/Drop.
        Covers B6 (Mullvad Keypair), B7 (Signal PrivateKey).

        Scans the entire file (not just the function) for struct definitions
        containing secret/key fields, and checks if they implement Zeroize.
        """
        findings = []
        if cpg.site.language.value != "rust":
            return findings

        # Scan the file AND sibling files in the same directory
        file_texts = []
        try:
            with open(cpg.site.file_path, "r", errors="replace") as f:
                file_texts.append((cpg.site.file_path, f.read()))
            # Also scan sibling .rs files in the same directory
            import os
            dir_path = os.path.dirname(cpg.site.file_path)
            for fname in os.listdir(dir_path):
                if fname.endswith(".rs") and fname != os.path.basename(cpg.site.file_path):
                    fpath = os.path.join(dir_path, fname)
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            file_texts.append((fpath, f.read()))
                    except OSError:
                        pass
        except OSError:
            return findings

        # Patterns for struct/type checks
        struct_pattern = re.compile(
            r"pub\s+struct\s+(\w*(?:Keypair|PrivateKey|SecretKey|SharedSecret|"
            r"KeyPair|DecapsulationKey|Secret)\w*)\s*[\{(]",
            re.IGNORECASE,
        )
        type_alias_pattern = re.compile(
            r"type\s+(\w*(?:SharedSecret|SecretKey|PrivateKey)\w*)\s*=\s*"
            r"(Box<\[u8\]>|Vec<u8>|\[u8;\s*\d+\])",
        )

        for scan_path, file_text in file_texts:
            for m in struct_pattern.finditer(file_text):
                struct_name = m.group(1)
                has_zeroize = bool(re.search(
                    rf"(#\[derive\(.*Zeroize.*\)\].*struct\s+{re.escape(struct_name)}|"
                    rf"impl\s+(?:Drop|Zeroize|ZeroizeOnDrop)\s+for\s+{re.escape(struct_name)})",
                    file_text, re.DOTALL,
                ))
                if not has_zeroize:
                    line_no = file_text[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        project=project,
                        file_path=scan_path,
                        function_name=struct_name,
                        sp="SP2", sub_property="SP2a",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"Rust struct '{struct_name}' at L{line_no} holds key material "
                            f"but does not implement Zeroize, ZeroizeOnDrop, or Drop."
                        ),
                        lines=[line_no],
                    ))

            for m in type_alias_pattern.finditer(file_text):
                alias_name = m.group(1)
                backing_type = m.group(2)
                line_no = file_text[:m.start()].count("\n") + 1
                findings.append(Finding(
                    project=project,
                    file_path=scan_path,
                    function_name=alias_name,
                    sp="SP2", sub_property="SP2a",
                    verdict=Verdict.FAIL, severity=Severity.HIGH,
                    evidence=(
                        f"Rust type alias '{alias_name} = {backing_type}' at L{line_no} "
                        f"holds key material without Zeroize."
                    ),
                    lines=[line_no],
                ))

        return findings

    # ── SP2 Go: secret buffers without explicit zeroing ──────────

    def _sp2_go_no_zeroize(self, cpg: FunctionCPG,
                            project: str) -> list[Finding]:
        """Detect Go secret buffers not explicitly zeroed.
        Go GC doesn't deterministically zero memory.
        Covers: Katzenpost A5, Go TLS SP2c.
        """
        findings = []
        body = cpg.site.body_text
        if cpg.site.language.value != "go":
            return findings

        # Pattern 1: sharedSecrets := make([][]byte, ...) with if err != nil { return }
        # Katzenpost A5: first SS stored, second decaps fails, first SS not cleared
        if "sharedSecrets" in body:
            # Check for sequential decapsulate/encapsulate with error returns
            lines = body.split("\n")
            decaps_lines = [(i, l) for i, l in enumerate(lines)
                            if re.search(r"\.Decapsulate\(|\.Encapsulate\(", l)]
            err_returns = [(i, l) for i, l in enumerate(lines)
                           if re.search(r"if\s+err\s*!=\s*nil", l)]

            if len(decaps_lines) >= 2 and err_returns:
                has_bzero = "ExplicitBzero" in body
                # Check if sharedSecrets is zeroed in error paths
                has_ss_cleanup = re.search(
                    r"for\s+.*range\s+sharedSecrets.*\{|ExplicitBzero.*sharedSecrets", body)
                if not has_bzero and not has_ss_cleanup:
                    findings.append(Finding(
                        project=project, file_path=cpg.site.file_path,
                        function_name=cpg.site.function_name,
                        sp="SP2", sub_property="SP2a",
                        verdict=Verdict.FAIL, severity=Severity.HIGH,
                        evidence=(
                            f"Go half-success: {len(decaps_lines)} sequential KEM "
                            f"decaps with error returns. If decaps[1] fails, "
                            f"sharedSecrets[0] persists on Go heap (GC non-deterministic). "
                            f"No ExplicitBzero on error paths."
                        ),
                    ))
                    return findings

        # Pattern 2: General Go shared secret without zeroing
        if "shared_secret" in body or "sharedKey" in body:
            has_bzero = "ExplicitBzero" in body or "explicit_bzero" in body
            if not has_bzero:
                findings.append(Finding(
                    project=project, file_path=cpg.site.file_path,
                    function_name=cpg.site.function_name,
                    sp="SP2", sub_property="SP2c",
                    verdict=Verdict.UNCERTAIN, severity=Severity.MEDIUM,
                    evidence=(
                        f"Go function handles shared secrets but has no explicit "
                        f"zeroing. Go GC does not deterministically zero memory."
                    ),
                ))

        return findings
