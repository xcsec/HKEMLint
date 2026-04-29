"""CPG (Code Property Graph) builder.

Constructs a true CPG with three edge layers on top of tree-sitter AST:

  Layer 1 — CFG edges:   control flow (sequential, branch, goto, return)
  Layer 2 — AST edges:   parent → child structural relationships
  Layer 3 — Dataflow edges: variable def → use chains

Edge types stored in FunctionCPG:
  "cfg" / "cfg_true" / "cfg_false"  — control flow
  "ast_child"                       — AST structural
  "dataflow"                        — data dependency (def → use)
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Optional

from hybridlint.cpg.models import (
    CPGEdge,
    CPGNode,
    CryptoLabel,
    FunctionCPG,
    HybridSite,
    Language,
)
from hybridlint.cpg.cfg_builder import CFGBuilder, EXIT_NODE_ID


# ──────────────────────────────────────────────────────────────────────
# Regex patterns for variable extraction
# ──────────────────────────────────────────────────────────────────────

# C/C++/Go/Rust assignment LHS:  target = expr
_ASSIGN_LHS_RE = re.compile(
    r"(?:^|[\s;{(,])"           # preceded by whitespace/delimiters
    r"(\*?\w[\w\[\]\.\-\>]*)"   # variable (may start with *)
    r"\s*(?::=|=)\s*"           # assignment operator (Go := or =)
    r"(?!=)",                    # not ==
)

# C declaration with init:  type var = expr;  or  type *var = expr;
_DECL_INIT_RE = re.compile(
    r"\b(?:u_char|uint8_t|byte|unsigned\s+char|char|int|size_t|"
    r"struct\s+\w+|const\s+\w+)\s+"
    r"(\*?\w+)"                 # variable name
    r"(?:\s*\[[^\]]*\])?"       # optional array brackets
    r"\s*=",
)

# Function call: func(arg1, arg2, ...)
_FUNC_CALL_RE = re.compile(r"(\w+)\s*\(")

# Extract all C identifiers (2+ chars, not keywords)
_IDENT_RE = re.compile(r"\b([a-zA-Z_]\w{1,})\b")

_C_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "return", "goto", "break", "continue", "struct", "union", "enum",
    "typedef", "sizeof", "static", "const", "void", "int", "char",
    "unsigned", "signed", "long", "short", "float", "double", "bool",
    "true", "false", "NULL", "nullptr", "new", "delete", "class",
    "public", "private", "protected", "virtual", "override", "template",
    "typename", "namespace", "using", "auto", "inline", "extern",
    "volatile", "register", "func", "var", "let", "mut", "fn", "pub",
    "impl", "trait", "match", "unsafe", "ref", "self", "Self",
    "package", "import", "type", "interface", "range", "defer",
    "byte", "string", "error", "nil", "make", "len", "cap", "append",
}

# Functions known to write to their first argument (out-parameter pattern)
_OUT_PARAM_FUNCTIONS = {
    # Crypto keygen / encaps / decaps
    "MLKEM768_encap", "MLKEM768_decap", "MLKEM1024_encap", "MLKEM1024_decap",
    "MLKEM768_generate_key", "MLKEM1024_generate_key",
    "X25519_keypair", "X25519", "X25519_public_from_private",
    "wc_KyberEncapsulate", "wc_KyberDecapsulate", "wc_KyberKey_MakeKey",
    "OQS_KEM_encaps", "OQS_KEM_decaps", "OQS_KEM_keypair",
    "EVP_PKEY_derive", "EVP_PKEY_keygen",
    "kexc25519_keygen",
    "libcrux_ml_kem_mlkem768_portable_encapsulate",
    "libcrux_ml_kem_mlkem768_portable_decapsulate",
    # Memory write
    "memcpy", "XMEMCPY", "memmove", "memset", "XMEMSET",
    # Zeroize (writes zeros to first arg)
    "ForceZero", "OPENSSL_cleanse", "explicit_bzero", "memset_s",
    "sodium_memzero", "SecureZeroMemory", "wipememory",
    # RNG (writes random to first arg)
    "RAND_bytes", "RAND_priv_bytes", "arc4random_buf",
    "wc_RNG_GenerateBlock", "getrandom", "OQS_randombytes",
    # Read
    "io.ReadFull",
}


def _extract_call_args(text: str) -> list[tuple[str, list[str]]]:
    """Extract (func_name, [arg1, arg2, ...]) from call expressions in text."""
    results = []
    for m in _FUNC_CALL_RE.finditer(text):
        func_name = m.group(1)
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        args_str = text[start:i - 1] if i > start else ""
        args = [a.strip() for a in args_str.split(",") if a.strip()]
        results.append((func_name, args))
    return results


def _clean_var_name(raw: str) -> str:
    """Normalize a variable reference to a simple identifier."""
    v = raw.strip().lstrip("&*").strip()
    v = re.sub(r"\[.*?\]", "", v)       # remove [index]
    v = re.sub(r"\(.*?\)", "", v)       # remove (cast)
    if "->" in v:
        v = v.split("->")[-1]
    if "." in v:
        v = v.split(".")[-1]
    return v.strip()


def _extract_identifiers(text: str) -> set[str]:
    """Extract all C-like identifiers from text, excluding keywords."""
    return {m.group(1) for m in _IDENT_RE.finditer(text)} - _C_KEYWORDS


class CPGBuilder:
    """Builds a full CPG (AST + CFG + Dataflow) for one function."""

    def __init__(self, site: HybridSite, func_node: Any, language: Language):
        self._site = site
        self._func_node = func_node
        self._lang = language
        self._cfg_builder = CFGBuilder(site, func_node, language)

    def build(self) -> FunctionCPG:
        """Build the complete CPG."""
        # Layer 1: CFG
        cpg = self._cfg_builder.build()

        # Layer 2: AST parent-child edges
        self._add_ast_edges(cpg)

        # Layer 3: Dataflow def-use edges
        self._add_dataflow_edges(cpg)

        return cpg

    # ──────────────────────────────────────────────────────────────
    # Layer 2: AST edges
    # ──────────────────────────────────────────────────────────────

    def _add_ast_edges(self, cpg: FunctionCPG) -> None:
        """Connect CPG nodes via AST parent-child relationships.

        For each CPG node, check if any other CPG node's ts_node is a
        descendant of this node's ts_node. We check all descendants
        (not just direct children) because the CFG builder may create
        nodes at different nesting levels.
        """
        if len(cpg.nodes) < 2:
            return

        # Build ts_node_id → cpg_node_id mapping
        ts_id_to_cpg: dict[int, int] = {}
        for n in cpg.nodes.values():
            if n.ts_node is not None:
                ts_id_to_cpg[id(n.ts_node)] = n.id

        # For each CPG node, walk ALL descendants of its ts_node
        for parent_cpg in list(cpg.nodes.values()):
            if parent_cpg.ts_node is None or parent_cpg.id == EXIT_NODE_ID:
                continue
            # Collect all descendant ts_node ids
            descendant_cpg_ids = set()
            self._collect_ts_descendants(
                parent_cpg.ts_node, ts_id_to_cpg, descendant_cpg_ids
            )
            descendant_cpg_ids.discard(parent_cpg.id)
            # Only add edges to direct structural children (avoid transitive)
            for child_ts_node in self._direct_named_children(parent_cpg.ts_node):
                child_cpg_id = ts_id_to_cpg.get(id(child_ts_node))
                if child_cpg_id is not None and child_cpg_id != parent_cpg.id:
                    cpg.add_edge(parent_cpg.id, child_cpg_id, "ast_child")
                else:
                    # Check if any CPG node exists deeper inside this child
                    for deep_id in descendant_cpg_ids:
                        deep_node = cpg.nodes.get(deep_id)
                        if deep_node and deep_node.ts_node is not None:
                            if self._is_ancestor(child_ts_node, deep_node.ts_node):
                                cpg.add_edge(parent_cpg.id, deep_id, "ast_child")

    def _collect_ts_descendants(self, ts_node: Any,
                                 ts_id_map: dict[int, int],
                                 result: set[int]) -> None:
        """Recursively find all CPG node ids that are descendants of ts_node."""
        try:
            for child in ts_node.named_children:
                cpg_id = ts_id_map.get(id(child))
                if cpg_id is not None:
                    result.add(cpg_id)
                self._collect_ts_descendants(child, ts_id_map, result)
        except Exception:
            pass

    @staticmethod
    def _direct_named_children(ts_node: Any) -> list:
        try:
            return list(ts_node.named_children)
        except Exception:
            return []

    @staticmethod
    def _is_ancestor(ancestor: Any, descendant: Any) -> bool:
        """Check if `ancestor` ts_node is a structural ancestor of `descendant`."""
        try:
            current = descendant.parent
            depth = 0
            while current is not None and depth < 50:
                if id(current) == id(ancestor):
                    return True
                current = current.parent
                depth += 1
        except Exception:
            pass
        return False

    # ──────────────────────────────────────────────────────────────
    # Layer 3: Dataflow edges
    # ──────────────────────────────────────────────────────────────

    def _add_dataflow_edges(self, cpg: FunctionCPG) -> None:
        """Add def→use dataflow edges for all identifiers in the function.

        Strategy:
        1. For each CPG node, extract defined vars (LHS of assignments,
           out-parameters of known functions)
        2. For each CPG node, extract all used identifiers
        3. For each variable: connect most-recent-def → use
        4. Keep ALL def-use edges (not just "interesting" ones) so
           checkers can trace any variable
        """
        sorted_nodes = sorted(
            (n for n in cpg.nodes.values() if n.id != EXIT_NODE_ID),
            key=lambda n: n.line,
        )

        # Pass 1: collect all definitions {var_name: [(node_id, line), ...]}
        all_defs: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for node in sorted_nodes:
            for var in self._extract_defs(node.text):
                all_defs[var].append((node.id, node.line))

        # Pass 2: for each node, find identifiers that have a prior def
        for node in sorted_nodes:
            idents = _extract_identifiers(node.text)
            for ident in idents:
                if ident not in all_defs:
                    continue
                # Find most recent def at or before this line
                best_def_id = None
                best_def_line = -1
                for def_id, def_line in all_defs[ident]:
                    if def_line <= node.line and def_line > best_def_line:
                        best_def_id = def_id
                        best_def_line = def_line
                # Don't self-loop (def node also contains the ident)
                if best_def_id is not None and best_def_id != node.id:
                    cpg.add_edge(best_def_id, node.id, "dataflow")

    def _extract_defs(self, text: str) -> list[str]:
        """Extract variable names that are defined/written in this statement."""
        result = []

        # 1. Assignment LHS: var = expr  or  var := expr
        for m in _ASSIGN_LHS_RE.finditer(text):
            var = _clean_var_name(m.group(1))
            if var and var not in _C_KEYWORDS and len(var) > 1:
                result.append(var)

        # 2. Declaration with init: type var = expr
        for m in _DECL_INIT_RE.finditer(text):
            var = _clean_var_name(m.group(1))
            if var and var not in _C_KEYWORDS and len(var) > 1:
                result.append(var)

        # 3. Out-parameter functions: func(dest, ...) writes to dest
        for func_name, args in _extract_call_args(text):
            if func_name in _OUT_PARAM_FUNCTIONS and args:
                var = _clean_var_name(args[0])
                if var and var not in _C_KEYWORDS and len(var) > 1:
                    result.append(var)

        # 4. C struct result assignment: result = func(...)
        #    Already covered by pattern 1

        return result


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def build_cpg(
    site: HybridSite,
    func_node: Any = None,
    language: Language = None,
) -> FunctionCPG:
    """Build a complete CPG (AST + CFG + Dataflow) for a hybrid function.

    Parameters
    ----------
    site : HybridSite
        Hybrid site metadata.
    func_node : optional
        tree-sitter function node. Defaults to site.ts_node.
    language : optional
        Language enum. Defaults to site.language.
    """
    if func_node is None:
        func_node = site.ts_node
    if language is None:
        language = site.language
    if func_node is None:
        return FunctionCPG(site=site)

    builder = CPGBuilder(site, func_node, language)
    return builder.build()
