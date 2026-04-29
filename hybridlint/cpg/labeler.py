"""Two-pass crypto-semantic labeler for CPG nodes.

Pass 1 — Assign ``op_label`` and ``component`` to every node via
         deterministic keyword matching.
Pass 2 — Assign ``val_label`` by combining op_label + component +
         variable-name heuristics + dataflow context.

Also sets the legacy ``CryptoLabel`` field for backward compatibility.
"""
from __future__ import annotations

import re
from typing import Optional

from hybridlint.cpg.models import (
    CPGNode, CryptoLabel, FunctionCPG, OpLabel, ValLabel,
)
from hybridlint.locator.keywords import (
    CLASSICAL_KEYWORDS,
    COMBINER_CONCAT,
    COMBINER_KDF,
    COMBINER_XOR,
    FREE_FUNCTIONS,
    HYBRID_GROUP_IDS,
    GROUP_CONFIG_KEYWORDS,
    PQC_KEYWORDS,
    RNG_FUNCTIONS,
    ZEROIZE_FUNCTIONS,
)

# ─── Keyword sets for fine-grained operation classification ─────────────

# Keygen functions
_KEYGEN_CLASSICAL = {
    "X25519_keypair", "X25519_public_from_private",
    "kexc25519_keygen", "EVP_PKEY_keygen",
    "wc_ecc_make_key", "EccMakeKey",
    "TLSX_KeyShare_GenEccKey", "TLSX_KeyShare_GenX25519Key",
    "GenerateKey", "generate_key",
    "crypto_scalarmult_curve25519_base",
    "ecdh.GenerateKey", "curve.GenerateKey",
    "generate_key_pair",
}
_KEYGEN_PQC = {
    "MLKEM768_generate_key", "MLKEM1024_generate_key",
    "OQS_KEM_keypair", "wc_KyberKey_MakeKey",
    "TLSX_KeyShare_GenPqcKey",
    "libcrux_ml_kem_mlkem768_portable_generate_key_pair",
    "libcrux_ml_kem_mlkem1024_portable_generate_key_pair",
    "ml_kem_keypair", "kem_keypairs",
    "MlKem768.generate_key_pair", "MlKem1024.generate_key_pair",
}

# Encapsulation functions
_ENCAP_CLASSICAL = {
    "X25519(", "crypto_scalarmult_curve25519",
    "EVP_PKEY_derive", "ECDH_compute_key",
    "wc_curve25519_shared_secret", "wc_ecc_shared_secret",
    "kexc25519_shared_key",
    "TLSX_KeyShare_ProcessEcc", "TLSX_KeyShare_ProcessX25519",
    "calculate_agreement", "key_agreement",
    "ecdh.ECDH",
}
_ENCAP_PQC = {
    "MLKEM768_encap", "MLKEM1024_encap",
    "OQS_KEM_encaps", "wc_KyberEncapsulate",
    "TLSX_KeyShare_ProcessPqcClient",
    "libcrux_ml_kem_mlkem768_portable_encapsulate",
    "libcrux_ml_kem_mlkem1024_portable_encapsulate",
    "Encapsulate(", "encapsulate(",
    "kem_encaps", "KEM_encapsulate",
}

# Decapsulation functions
_DECAP_CLASSICAL = set()  # DH is symmetric; same functions as ENCAP
_DECAP_PQC = {
    "MLKEM768_decap", "MLKEM1024_decap",
    "OQS_KEM_decaps", "wc_KyberDecapsulate",
    "libcrux_ml_kem_mlkem768_portable_decapsulate",
    "libcrux_ml_kem_mlkem1024_portable_decapsulate",
    "Decapsulate(", "decapsulate(",
    "kem_decaps", "KEM_decapsulate",
}

# ─── Regex patterns ────────────────────────────────────────────────────

_CALL_RE = re.compile(r"(\w+)\s*\(")
_ASSIGN_RE = re.compile(r"(\w[\w\[\]\.\->]*)\s*=\s*")

_CALL_KINDS = {
    "call_expression", "function_call", "macro_invocation",
    "method_call_expression", "call_expr",
}
_ASSIGN_KINDS = {
    "assignment_expression", "init_declarator", "declaration",
    "variable_declaration", "let_declaration", "short_var_declaration",
    "assignment_statement",
}
_IF_KINDS = {"if_statement", "if_expression", "if_let_expression"}

_GOTO_RE = re.compile(r"\bgoto\s+\w+")
_RETURN_ERR_RE = re.compile(
    r"\breturn\s+("
    r"-\d+|err\b|error\b|ret\b|FAILURE|WOLFSSL_FAILURE"
    r"|SSL_FATAL_ERROR|MEMORY_E|BAD_FUNC_ARG"
    r")",
    re.IGNORECASE,
)

_ERR_CHECK_RES = [
    re.compile(r"\bif\s*\(\s*ret\s*!=\s*0\b"),
    re.compile(r"\bif\s*\(\s*ret\s*<\s*0\b"),
    re.compile(r"\bif\s*\(\s*ret\s*<=\s*0\b"),
    re.compile(r"\bif\s*\(\s*\w+\s*!=\s*(?:SSL_SUCCESS|WOLFSSL_SUCCESS|0|OQS_SUCCESS)\b"),
    re.compile(r"\bif\s*\(\s*ret\s*==\s*0\s*\)"),
    re.compile(r"\bif\s*\(\s*\w+\s*==\s*NULL\b"),
    re.compile(r"\bif\s*\(\s*!\s*\w+\s*\)"),
    re.compile(r"\bON_ERR_SET_GOTO\b"),
    re.compile(r"\bON_ERR_GOTO\b"),
    re.compile(r"\bif\s+err\s*!=\s*nil\b"),
    re.compile(r"\?\s*;"),
    re.compile(r"\bif\s*\(\s*!CBS_"),
    re.compile(r"\bif\s*\(\s*!MLKEM"),
    re.compile(r"\bif\s*\(\s*!X25519\b"),
]

# Buffer-name heuristic
_BUF_NAME_RE = re.compile(
    r"\b(\w*(?:secret|key|ss|buf|preMasterSecret|shared)\w*)\b",
    re.IGNORECASE,
)

# Group config array
_GROUP_CONFIG_ARRAY_RE = re.compile(
    r"(?:static\s+)?(?:const\s+)?\w[\w\s\*]*\[\]\s*=\s*\{",
)

# ─── Value-label variable-name patterns ────────────────────────────────

# Classical shared secret  → K_1
_K1_VAR_RE = re.compile(
    r"\b\w*(x25519_ss|ecdh_secret|classical_secret|dh_shared|"
    r"x25519_shared|curve25519_shared|ecc_shared|"
    r"sntrup_ss|sntrup761_ss)\w*\b",
    re.IGNORECASE,
)

# PQC shared secret → K_2
_K2_VAR_RE = re.compile(
    r"\b\w*(mlkem_ss|kem_secret|pqc_secret|kyber_ss|"
    r"mlkem_shared|kyber_shared|kem_shared|pq_ss|"
    r"brace_shared)\w*\b",
    re.IGNORECASE,
)

# Combined shared secret → K
_K_VAR_RE = re.compile(
    r"\b\w*(combined_secret|hybrid_secret|final_secret|"
    r"master_secret|preMasterSecret|handshake_secret)\w*\b",
    re.IGNORECASE,
)

# Classical public key → ek_1
_EK1_VAR_RE = re.compile(
    r"\b\w*(x25519_pub|ecdh_pub|classical_pub|"
    r"our_ephemeral_pub|peer_pub_x25519)\w*\b",
    re.IGNORECASE,
)

# PQC encapsulation key → ek_2
_EK2_VAR_RE = re.compile(
    r"\b\w*(mlkem_ek|kyber_pub|pqc_pub|kem_pub|"
    r"mlkem_pub|encapsulation_key|brace_ek)\w*\b",
    re.IGNORECASE,
)

# Classical private key → dk_1
_DK1_VAR_RE = re.compile(
    r"\b\w*(x25519_priv|ecdh_priv|classical_priv|"
    r"our_base_private|identity_key_priv)\w*\b",
    re.IGNORECASE,
)

# PQC decapsulation key → dk_2
_DK2_VAR_RE = re.compile(
    r"\b\w*(mlkem_dk|kyber_priv|pqc_priv|kem_priv|"
    r"decapsulation_key|brace_dk)\w*\b",
    re.IGNORECASE,
)

# Classical ciphertext → c_1
_C1_VAR_RE = re.compile(
    r"\b\w*(x25519_ct|ecdh_ct|classical_ct|"
    r"x25519_ciphertext|dh_public)\w*\b",
    re.IGNORECASE,
)

# PQC ciphertext → c_2
_C2_VAR_RE = re.compile(
    r"\b\w*(mlkem_ct|kyber_ct|pqc_ct|kem_ct|"
    r"kem_ciphertext|brace_ct)\w*\b",
    re.IGNORECASE,
)


# ─── Helpers ───────────────────────────────────────────────────────────

def _text_contains_any(text: str, keywords: set[str]) -> bool:
    for kw in keywords:
        if kw in text:
            return True
    return False


def _first_matching_keyword(text: str, keywords: set[str]) -> Optional[str]:
    for kw in keywords:
        if kw in text:
            return kw
    return None


def _is_call_or_assign(node: CPGNode) -> bool:
    if node.kind in _CALL_KINDS or node.kind in _ASSIGN_KINDS:
        return True
    if _CALL_RE.search(node.text) or _ASSIGN_RE.search(node.text):
        return True
    return False


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    return text


def _extract_target_buffer(text: str) -> str:
    m = _ASSIGN_RE.search(text)
    if m:
        lhs = m.group(1)
        bm = _BUF_NAME_RE.search(lhs)
        return bm.group(1) if bm else lhs
    call = _CALL_RE.search(text)
    if call:
        start = call.end()
        depth, i = 1, start
        while i < len(text) and depth > 0:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        args_str = text[start:i - 1] if i > start else ""
        args = [a.strip() for a in args_str.split(",") if a.strip()]
        if args:
            bm = _BUF_NAME_RE.search(args[0])
            return bm.group(1) if bm else args[0]
    return ""


def _is_skippable(node: CPGNode) -> bool:
    """Return True if node is a comment / preprocessor / debug line."""
    if node.kind == "comment":
        return True
    stripped = node.text.strip()
    if stripped.startswith(("#ifdef", "#endif", "#if ", "#else")):
        return True
    if re.search(r"\b(dump_digest|DEBUG_KEXECDH|debug\s*\(|printf|fprintf|WLOG)\b",
                 node.text):
        return True
    if stripped.startswith(("/*", "//", "*")):
        code = re.sub(r"/\*.*?\*/", "", node.text, flags=re.DOTALL)
        code = re.sub(r"//.*$", "", code, flags=re.MULTILINE).strip()
        if not code:
            return True
    return False


# ─── Secret-buffer keywords (legacy) ──────────────────────────────────

SECRET_BUF_KEYWORDS = {
    "secret", "shared_key", "preMasterSecret", "ss", "shared_secret",
}


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def label_nodes(cpg: FunctionCPG) -> FunctionCPG:
    """Label every node in *cpg* with op_label, val_label, and component.

    Also sets the legacy ``CryptoLabel`` for backward compatibility.
    Modifies *cpg* in-place and returns it.
    """
    # Pass 1: op_label + component + legacy label
    for node in cpg.nodes.values():
        _pass1_op_label(node)

    # Pass 2: val_label (uses op_label + component + variable names)
    for node in cpg.nodes.values():
        _pass2_val_label(node, cpg)

    return cpg


# ═══════════════════════════════════════════════════════════════════════
# Pass 1: Operation label + component
# ═══════════════════════════════════════════════════════════════════════

def _pass1_op_label(node: CPGNode) -> None:
    """Assign op_label, component, and legacy CryptoLabel to one node."""
    if _is_skippable(node):
        node.op_label = OpLabel.NONE
        node.label = CryptoLabel.OTHER
        return

    text = node.text
    code = _strip_comments(text)

    # ── 1. ZEROIZE ──────────────────────────────────────────────────
    if _text_contains_any(text, ZEROIZE_FUNCTIONS):
        node.op_label = OpLabel.ZEROIZE
        node.label = CryptoLabel.ZEROIZE
        node.detail = _extract_target_buffer(text)
        return

    # ── 2. FREE (no zeroize) — legacy only, op stays NONE ──────────
    if _text_contains_any(text, FREE_FUNCTIONS):
        node.op_label = OpLabel.NONE
        node.label = CryptoLabel.FREE_NO_ZERO
        node.detail = _extract_target_buffer(text)
        return

    # ── 3. ERROR_CHECK ──────────────────────────────────────────────
    if node.kind in _IF_KINDS or node.kind == "expression_statement":
        for pat in _ERR_CHECK_RES:
            m = pat.search(text)
            if m:
                node.op_label = OpLabel.ERROR_CHECK
                node.label = CryptoLabel.ERROR_CHECK
                node.detail = m.group(0).strip()
                return

    # ── 4. ERROR_HANDLER (goto / error return) ─────────────────────
    if _GOTO_RE.search(text):
        node.op_label = OpLabel.ERROR_HANDLER
        node.label = CryptoLabel.ERROR_HANDLER
        m = _GOTO_RE.search(text)
        node.detail = m.group(0) if m else ""
        return
    if _RETURN_ERR_RE.search(text):
        node.op_label = OpLabel.ERROR_HANDLER
        node.label = CryptoLabel.ERROR_HANDLER
        node.detail = _RETURN_ERR_RE.search(text).group(0)
        return

    # ── 5. RNG ──────────────────────────────────────────────────────
    if _text_contains_any(text, RNG_FUNCTIONS) and _is_call_or_assign(node):
        node.op_label = OpLabel.RNG
        node.label = CryptoLabel.RNG_CALL
        node.detail = _first_matching_keyword(text, RNG_FUNCTIONS) or ""
        return

    # ── 6. COMBINER (KDF / XOR / concat) ───────────────────────────
    if _text_contains_any(code, COMBINER_KDF) and _is_call_or_assign(node):
        node.op_label = OpLabel.COMBINER
        node.label = CryptoLabel.COMBINER
        node.detail = "kdf"
        return
    if _text_contains_any(code, COMBINER_XOR) and _is_call_or_assign(node):
        node.op_label = OpLabel.COMBINER
        node.label = CryptoLabel.COMBINER
        node.detail = "xor"
        return
    if _text_contains_any(code, COMBINER_CONCAT) and _is_call_or_assign(node):
        node.op_label = OpLabel.COMBINER
        node.label = CryptoLabel.COMBINER
        node.detail = "concat"
        return

    # ── 7. CONFIG (group configuration) ────────────────────────────
    if _text_contains_any(text, GROUP_CONFIG_KEYWORDS) and (
        _GROUP_CONFIG_ARRAY_RE.search(text) or node.kind in _ASSIGN_KINDS
    ):
        node.op_label = OpLabel.CONFIG
        node.label = CryptoLabel.GROUP_CONFIG
        node.detail = _first_matching_keyword(text, GROUP_CONFIG_KEYWORDS) or ""
        return

    # ── 8. PARAM (hybrid group ID constants) ───────────────────────
    if _text_contains_any(text, HYBRID_GROUP_IDS):
        node.op_label = OpLabel.PARAM
        node.label = CryptoLabel.PARAM_CONST
        node.detail = _first_matching_keyword(text, HYBRID_GROUP_IDS) or ""
        return

    # ── 9. Fine-grained crypto operation ───────────────────────────
    if _is_call_or_assign(node):
        op, comp = _classify_crypto_op(text)
        if op != OpLabel.NONE:
            node.op_label = op
            node.component = comp
            node.label = (CryptoLabel.PQC_OP if comp == 2
                          else CryptoLabel.CLASSICAL_OP if comp == 1
                          else CryptoLabel.OTHER)
            node.detail = _extract_target_buffer(text)
            return

    # ── 10. SECRET_BUF (legacy) ────────────────────────────────────
    if _text_contains_any(text, SECRET_BUF_KEYWORDS) and node.kind in _ASSIGN_KINDS:
        node.label = CryptoLabel.SECRET_BUF
        node.detail = _extract_target_buffer(text)
        # op_label stays NONE — val_label will be assigned in pass 2
        return

    # ── 11. Fallback ───────────────────────────────────────────────
    node.op_label = OpLabel.NONE
    node.label = CryptoLabel.OTHER


def _classify_crypto_op(text: str) -> tuple[OpLabel, int]:
    """Classify a node text into (OpLabel, component).

    Returns (OpLabel.NONE, 0) if no match.
    Priority: DECAP > ENCAP > KEYGEN (more specific first).
    """
    # PQC decap
    if _text_contains_any(text, _DECAP_PQC):
        return OpLabel.DECAP, 2

    # PQC encap
    if _text_contains_any(text, _ENCAP_PQC):
        return OpLabel.ENCAP, 2

    # PQC keygen
    if _text_contains_any(text, _KEYGEN_PQC):
        return OpLabel.KEYGEN, 2

    # Classical keygen (check before encap since keygen is more specific)
    if _text_contains_any(text, _KEYGEN_CLASSICAL):
        return OpLabel.KEYGEN, 1

    # Classical DH (encap or decap based on context — default to ENCAP)
    if _text_contains_any(text, _ENCAP_CLASSICAL):
        return OpLabel.ENCAP, 1

    # Fallback: generic PQC / classical keyword check
    if _text_contains_any(text, PQC_KEYWORDS):
        return _guess_op_from_text(text), 2
    if _text_contains_any(text, CLASSICAL_KEYWORDS):
        return _guess_op_from_text(text), 1

    return OpLabel.NONE, 0


def _guess_op_from_text(text: str) -> OpLabel:
    """Best-effort guess of op type from generic keywords in text."""
    lower = text.lower()
    if "decap" in lower or "decapsulate" in lower:
        return OpLabel.DECAP
    if "encap" in lower or "encapsulate" in lower:
        return OpLabel.ENCAP
    if "keygen" in lower or "generate_key" in lower or "keypair" in lower:
        return OpLabel.KEYGEN
    # DH shared secret computation defaults to ENCAP
    if any(kw in lower for kw in ("shared_secret", "derive", "agreement")):
        return OpLabel.ENCAP
    return OpLabel.ENCAP  # conservative default for crypto ops


# ═══════════════════════════════════════════════════════════════════════
# Pass 2: Value label
# ═══════════════════════════════════════════════════════════════════════

def _pass2_val_label(node: CPGNode, cpg: FunctionCPG) -> None:
    """Assign val_label based on op_label + component + variable names."""
    if node.id == -1:
        return

    text = node.text

    # ── Strategy 1: infer from op_label + component ────────────────
    if node.op_label == OpLabel.COMBINER:
        node.val_label = ValLabel.K
        return

    if node.op_label in (OpLabel.ENCAP, OpLabel.DECAP):
        # The primary security-relevant output is the shared secret
        if node.component == 1:
            node.val_label = ValLabel.K_1
        elif node.component == 2:
            node.val_label = ValLabel.K_2
        return

    if node.op_label == OpLabel.KEYGEN:
        # Keygen produces ek + dk; label the node as dk (more sensitive)
        if node.component == 1:
            node.val_label = ValLabel.dk_1
        elif node.component == 2:
            node.val_label = ValLabel.dk_2
        return

    # ── Strategy 2: variable-name heuristics ───────────────────────
    if _K_VAR_RE.search(text):
        node.val_label = ValLabel.K
        return
    if _K1_VAR_RE.search(text):
        node.val_label = ValLabel.K_1
        return
    if _K2_VAR_RE.search(text):
        node.val_label = ValLabel.K_2
        return
    if _EK1_VAR_RE.search(text):
        node.val_label = ValLabel.ek_1
        return
    if _EK2_VAR_RE.search(text):
        node.val_label = ValLabel.ek_2
        return
    if _DK1_VAR_RE.search(text):
        node.val_label = ValLabel.dk_1
        return
    if _DK2_VAR_RE.search(text):
        node.val_label = ValLabel.dk_2
        return
    if _C1_VAR_RE.search(text):
        node.val_label = ValLabel.c_1
        return
    if _C2_VAR_RE.search(text):
        node.val_label = ValLabel.c_2
        return

    # ── Strategy 3: generic shared-secret near crypto op ───────────
    if node.label == CryptoLabel.SECRET_BUF:
        # Try to infer component from dataflow predecessors
        pred_ids = cpg.get_dataflow_predecessors(node.id, max_depth=3)
        for pid in pred_ids:
            pnode = cpg.nodes.get(pid)
            if pnode and pnode.component == 1:
                node.val_label = ValLabel.K_1
                node.component = 1
                return
            if pnode and pnode.component == 2:
                node.val_label = ValLabel.K_2
                node.component = 2
                return
        # Can't determine component — leave as NONE

    # val_label stays NONE
