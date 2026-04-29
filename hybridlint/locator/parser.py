"""Multi-language source code parser using tree-sitter."""
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Any, Optional

import tree_sitter
import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_rust
import tree_sitter_go
import tree_sitter_java

from hybridlint.cpg.models import Language, EXTENSION_TO_LANG


@dataclass
class FunctionNode:
    """A parsed function from source code."""
    name: str
    start_line: int
    end_line: int
    body_text: str
    language: Language
    file_path: str
    ts_node: Any


# Language grammar loaders
_LANG_MODULES = {
    Language.C: tree_sitter_c,
    Language.CPP: tree_sitter_cpp,
    Language.RUST: tree_sitter_rust,
    Language.GO: tree_sitter_go,
    Language.JAVA: tree_sitter_java,
}

# tree-sitter node types that represent function definitions
_FUNC_NODE_TYPES = {
    Language.C: {"function_definition"},
    Language.CPP: {"function_definition", "template_declaration"},
    Language.RUST: {"function_item"},
    Language.GO: {"function_declaration", "method_declaration"},
    Language.JAVA: {"method_declaration", "constructor_declaration"},
}

# Cached parser instances
_parsers: dict[Language, tree_sitter.Parser] = {}


def _get_parser(lang: Language) -> tree_sitter.Parser:
    if lang not in _parsers:
        parser = tree_sitter.Parser()
        parser.language = tree_sitter.Language(_LANG_MODULES[lang].language())
        _parsers[lang] = parser
    return _parsers[lang]


def detect_language(file_path: str) -> Optional[Language]:
    ext = os.path.splitext(file_path)[1].lower()
    return EXTENSION_TO_LANG.get(ext)


def parse_file(file_path: str) -> Optional[tree_sitter.Tree]:
    """Parse a source file and return the tree-sitter tree."""
    lang = detect_language(file_path)
    if lang is None:
        return None
    parser = _get_parser(lang)
    try:
        with open(file_path, "rb") as f:
            source = f.read()
        return parser.parse(source)
    except (OSError, UnicodeDecodeError):
        return None


def _get_function_name(node: tree_sitter.Node, lang: Language) -> str:
    """Extract function name from a function definition node."""
    if lang in (Language.C, Language.CPP):
        # function_definition -> declarator -> (function_declarator -> declarator)
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            return "<anonymous>"
        # Walk down to find the actual name
        while declarator.type in (
            "function_declarator", "pointer_declarator",
            "reference_declarator", "parenthesized_declarator",
        ):
            inner = declarator.child_by_field_name("declarator")
            if inner is None:
                break
            declarator = inner
        # C++ qualified name (class::method)
        if declarator.type == "qualified_identifier":
            return declarator.text.decode("utf-8", errors="replace")
        if declarator.type == "field_identifier":
            return declarator.text.decode("utf-8", errors="replace")
        if declarator.type == "identifier":
            return declarator.text.decode("utf-8", errors="replace")
        # template_declaration wraps function_definition
        if node.type == "template_declaration":
            for child in node.children:
                if child.type == "function_definition":
                    return _get_function_name(child, lang)
        return declarator.text.decode("utf-8", errors="replace")

    elif lang == Language.RUST:
        name_node = node.child_by_field_name("name")
        return name_node.text.decode("utf-8") if name_node else "<anonymous>"

    elif lang == Language.GO:
        name_node = node.child_by_field_name("name")
        return name_node.text.decode("utf-8") if name_node else "<anonymous>"

    elif lang == Language.JAVA:
        name_node = node.child_by_field_name("name")
        return name_node.text.decode("utf-8") if name_node else "<anonymous>"

    return "<unknown>"


def extract_functions(file_path: str) -> list[FunctionNode]:
    """Extract all function definitions from a source file."""
    lang = detect_language(file_path)
    if lang is None:
        return []

    tree = parse_file(file_path)
    if tree is None:
        return []

    try:
        with open(file_path, "r", errors="replace") as f:
            source_text = f.read()
    except OSError:
        return []

    func_types = _FUNC_NODE_TYPES.get(lang, set())
    functions = []

    # C++ container types that should be recursed into
    _CPP_CONTAINERS = {
        "namespace_definition", "class_specifier", "struct_specifier",
        "template_declaration", "linkage_specification",
        "declaration", "field_declaration_list",
    }

    def _walk(node: tree_sitter.Node):
        if node.type in func_types:
            name = _get_function_name(node, lang)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            body = node.text.decode("utf-8", errors="replace")
            # C++: if the "function" is actually a namespace or class body,
            # recurse into it instead of treating it as a single function.
            if lang in (Language.C, Language.CPP):
                is_container = (
                    name in ("namespace", "<anonymous>")
                    or (
                        ("class " in body[:200] or "struct " in body[:200])
                        and "(" not in name  # actual functions have () in declarator
                        and not body.strip().startswith("static ")
                        and not body.strip().startswith("int ")
                        and not body.strip().startswith("void ")
                        and not body.strip().startswith("bool ")
                    )
                )
                if is_container:
                    for child in node.children:
                        _walk(child)
                    return
            functions.append(FunctionNode(
                name=name,
                start_line=start_line,
                end_line=end_line,
                body_text=body,
                language=lang,
                file_path=file_path,
                ts_node=node,
            ))
            return  # Don't recurse into function bodies
        # Always recurse through containers (namespaces, classes, etc.)
        for child in node.children:
            _walk(child)

    _walk(tree.root_node)
    return functions
