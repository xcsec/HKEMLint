from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Optional

from hkemlint.cpg.models import (
    CPGEdge,
    CPGNode,
    CryptoLabel,
    FunctionCPG,
    HybridSite,
    Language,
)
from hkemlint.cpg.cfg_builder import CFGBuilder, EXIT_NODE_ID


_ASSIGN_LHS_RE = re.compile(
    r"(?:^|[\s;{(,])"
    r"(\*?\w[\w\[\]\.\-\>]*)"
    r"\s*(?::=|=)\s*"
    r"(?!=)",
)

_DECL_INIT_RE = re.compile(
    r"\b(?:u_char|uint8_t|byte|unsigned\s+char|char|int|size_t|"
    r"struct\s+\w+|const\s+\w+)\s+"
    r"(\*?\w+)"
    r"(?:\s*\[[^\]]*\])?"
    r"\s*=",
)

_FUNC_CALL_RE = re.compile(r"(\w+)\s*\(")

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

_OUT_PARAM_FUNCTIONS = {
    "MLKEM768_encap", "MLKEM768_decap", "MLKEM1024_encap", "MLKEM1024_decap",
    "MLKEM768_generate_key", "MLKEM1024_generate_key",
    "X25519_keypair", "X25519", "X25519_public_from_private",
    "wc_KyberEncapsulate", "wc_KyberDecapsulate", "wc_KyberKey_MakeKey",
    "OQS_KEM_encaps", "OQS_KEM_decaps", "OQS_KEM_keypair",
    "EVP_PKEY_derive", "EVP_PKEY_keygen",
    "kexc25519_keygen",
    "libcrux_ml_kem_mlkem768_portable_encapsulate",
    "libcrux_ml_kem_mlkem768_portable_decapsulate",
    "memcpy", "XMEMCPY", "memmove", "memset", "XMEMSET",
    "ForceZero", "OPENSSL_cleanse", "explicit_bzero", "memset_s",
    "sodium_memzero", "SecureZeroMemory", "wipememory",
    "RAND_bytes", "RAND_priv_bytes", "arc4random_buf",
    "wc_RNG_GenerateBlock", "getrandom", "OQS_randombytes",
    "io.ReadFull",
}


def _extract_call_args(text: str) -> list[tuple[str, list[str]]]:
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
    v = raw.strip().lstrip("&*").strip()
    v = re.sub(r"\[.*?\]", "", v)
    v = re.sub(r"\(.*?\)", "", v)
    if "->" in v:
        v = v.split("->")[-1]
    if "." in v:
        v = v.split(".")[-1]
    return v.strip()


def _extract_identifiers(text: str) -> set[str]:
    return {m.group(1) for m in _IDENT_RE.finditer(text)} - _C_KEYWORDS


class CPGBuilder:

    def __init__(self, site: HybridSite, func_node: Any, language: Language):
        self._site = site
        self._func_node = func_node
        self._lang = language
        self._cfg_builder = CFGBuilder(site, func_node, language)

    def build(self) -> FunctionCPG:
        cpg = self._cfg_builder.build()

        self._add_ast_edges(cpg)

        self._add_dataflow_edges(cpg)

        return cpg


    def _add_ast_edges(self, cpg: FunctionCPG) -> None:
        if len(cpg.nodes) < 2:
            return

        ts_id_to_cpg: dict[int, int] = {}
        for n in cpg.nodes.values():
            if n.ts_node is not None:
                ts_id_to_cpg[id(n.ts_node)] = n.id

        for parent_cpg in list(cpg.nodes.values()):
            if parent_cpg.ts_node is None or parent_cpg.id == EXIT_NODE_ID:
                continue
            descendant_cpg_ids = set()
            self._collect_ts_descendants(
                parent_cpg.ts_node, ts_id_to_cpg, descendant_cpg_ids
            )
            descendant_cpg_ids.discard(parent_cpg.id)
            for child_ts_node in self._direct_named_children(parent_cpg.ts_node):
                child_cpg_id = ts_id_to_cpg.get(id(child_ts_node))
                if child_cpg_id is not None and child_cpg_id != parent_cpg.id:
                    cpg.add_edge(parent_cpg.id, child_cpg_id, "ast_child")
                else:
                    for deep_id in descendant_cpg_ids:
                        deep_node = cpg.nodes.get(deep_id)
                        if deep_node and deep_node.ts_node is not None:
                            if self._is_ancestor(child_ts_node, deep_node.ts_node):
                                cpg.add_edge(parent_cpg.id, deep_id, "ast_child")

    def _collect_ts_descendants(self, ts_node: Any,
                                 ts_id_map: dict[int, int],
                                 result: set[int]) -> None:
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


    def _add_dataflow_edges(self, cpg: FunctionCPG) -> None:
        sorted_nodes = sorted(
            (n for n in cpg.nodes.values() if n.id != EXIT_NODE_ID),
            key=lambda n: n.line,
        )

        all_defs: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for node in sorted_nodes:
            for var in self._extract_defs(node.text):
                all_defs[var].append((node.id, node.line))

        for node in sorted_nodes:
            idents = _extract_identifiers(node.text)
            for ident in idents:
                if ident not in all_defs:
                    continue
                best_def_id = None
                best_def_line = -1
                for def_id, def_line in all_defs[ident]:
                    if def_line <= node.line and def_line > best_def_line:
                        best_def_id = def_id
                        best_def_line = def_line
                if best_def_id is not None and best_def_id != node.id:
                    cpg.add_edge(best_def_id, node.id, "dataflow")

    def _extract_defs(self, text: str) -> list[str]:
        result = []

        for m in _ASSIGN_LHS_RE.finditer(text):
            var = _clean_var_name(m.group(1))
            if var and var not in _C_KEYWORDS and len(var) > 1:
                result.append(var)

        for m in _DECL_INIT_RE.finditer(text):
            var = _clean_var_name(m.group(1))
            if var and var not in _C_KEYWORDS and len(var) > 1:
                result.append(var)

        for func_name, args in _extract_call_args(text):
            if func_name in _OUT_PARAM_FUNCTIONS and args:
                var = _clean_var_name(args[0])
                if var and var not in _C_KEYWORDS and len(var) > 1:
                    result.append(var)


        return result


def build_cpg(
    site: HybridSite,
    func_node: Any = None,
    language: Language = None,
) -> FunctionCPG:
    if func_node is None:
        func_node = site.ts_node
    if language is None:
        language = site.language
    if func_node is None:
        return FunctionCPG(site=site)

    builder = CPGBuilder(site, func_node, language)
    return builder.build()
