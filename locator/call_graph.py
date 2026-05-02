from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from hkemlint.locator.parser import extract_functions, FunctionNode


@dataclass
class ExpandedSite:
    primary: FunctionNode
    callees: list[FunctionNode]
    callers: list[FunctionNode]

    @property
    def combined_body(self) -> str:
        parts = [self.primary.body_text]
        for callee in self.callees:
            parts.append(f"\n// --- callee: {callee.name} ---\n{callee.body_text}")
        return "\n".join(parts)


_CALL_RE = re.compile(r"\b(\w{3,})\s*\(")

_SKIP_FUNCTIONS = {
    "if", "for", "while", "switch", "return", "sizeof", "typeof",
    "printf", "fprintf", "sprintf", "snprintf", "memcpy", "memset",
    "malloc", "calloc", "realloc", "free", "strlen", "strcmp",
    "XMALLOC", "XFREE", "XMEMCPY", "XMEMSET",
}


def extract_callees(func: FunctionNode,
                     project_functions: dict[str, FunctionNode]) -> list[FunctionNode]:
    body = func.body_text
    called_names = set()
    for m in _CALL_RE.finditer(body):
        name = m.group(1)
        if name not in _SKIP_FUNCTIONS:
            called_names.add(name)

    callees = []
    for name in called_names:
        if name in project_functions and name != func.name:
            callees.append(project_functions[name])
    return callees


def extract_callers(func_name: str,
                     project_functions: dict[str, FunctionNode]) -> list[FunctionNode]:
    callers = []
    pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    for name, fn in project_functions.items():
        if name != func_name and pattern.search(fn.body_text):
            callers.append(fn)
    return callers


def build_project_function_index(project_path: str,
                                   source_files: list[str] = None) -> dict[str, FunctionNode]:
    index: dict[str, FunctionNode] = {}
    if source_files is None:
        from hkemlint.locator.site_finder import walk_source_files
        source_files = walk_source_files(project_path)

    for fpath in source_files:
        try:
            funcs = extract_functions(fpath)
            for f in funcs:
                if f.name not in index:
                    index[f.name] = f
        except Exception:
            continue
    return index


def expand_site(func: FunctionNode,
                 project_functions: dict[str, FunctionNode]) -> ExpandedSite:
    callees = extract_callees(func, project_functions)
    callers = extract_callers(func.name, project_functions)
    return ExpandedSite(primary=func, callees=callees, callers=callers)
