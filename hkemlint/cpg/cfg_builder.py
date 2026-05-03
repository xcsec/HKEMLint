from __future__ import annotations

from typing import Any, Optional

import networkx as nx  # type: ignore

from hkemlint.cpg.models import (
    CPGEdge,
    CPGNode,
    CryptoLabel,
    FunctionCPG,
    HybridSite,
    Language,
)


_COMPOUND_TYPES: dict[Language, set[str]] = {
    Language.C: {"compound_statement", "translation_unit"},
    Language.CPP: {"compound_statement", "translation_unit"},
    Language.RUST: {"block", "match_block"},
    Language.GO: {"block"},
    Language.JAVA: {"block"},
}

_IF_TYPES: dict[Language, set[str]] = {
    Language.C: {"if_statement"},
    Language.CPP: {"if_statement"},
    Language.RUST: {"if_expression"},
    Language.GO: {"if_statement"},
    Language.JAVA: {"if_statement"},
}

_RETURN_TYPES: dict[Language, set[str]] = {
    Language.C: {"return_statement"},
    Language.CPP: {"return_statement"},
    Language.RUST: {"return_expression"},
    Language.GO: {"return_statement"},
    Language.JAVA: {"return_statement"},
}

_LOOP_TYPES: dict[Language, set[str]] = {
    Language.C: {"for_statement", "while_statement", "do_statement"},
    Language.CPP: {"for_statement", "while_statement", "do_statement"},
    Language.RUST: {"for_expression", "while_expression", "loop_expression"},
    Language.GO: {"for_statement"},
    Language.JAVA: {"for_statement", "while_statement", "do_statement",
                    "enhanced_for_statement"},
}

_SWITCH_TYPES: dict[Language, set[str]] = {
    Language.C: {"switch_statement"},
    Language.CPP: {"switch_statement"},
    Language.RUST: {"match_expression"},
    Language.GO: {"expression_switch_statement", "type_switch_statement"},
    Language.JAVA: {"switch_expression", "switch_statement"},
}

_GOTO_TYPES: dict[Language, set[str]] = {
    Language.C: {"goto_statement"},
    Language.CPP: {"goto_statement"},
    Language.RUST: set(),
    Language.GO: {"goto_statement"},
    Language.JAVA: set(),
}

_LABEL_TYPES: dict[Language, set[str]] = {
    Language.C: {"labeled_statement"},
    Language.CPP: {"labeled_statement"},
    Language.RUST: set(),
    Language.GO: {"labeled_statement"},
    Language.JAVA: {"labeled_statement"},
}

_THROW_TYPES: dict[Language, set[str]] = {
    Language.C: set(),
    Language.CPP: {"throw_statement"},
    Language.RUST: set(),
    Language.GO: set(),
    Language.JAVA: {"throw_statement"},
}

_TRY_TYPES: dict[Language, set[str]] = {
    Language.C: set(),
    Language.CPP: {"try_statement"},
    Language.RUST: set(),
    Language.GO: set(),
    Language.JAVA: {"try_statement"},
}

EXIT_NODE_ID: int = -1


def _node_text(ts_node: Any) -> str:
    try:
        raw = ts_node.text
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if len(raw) > 200:
            return raw[:197] + "..."
        return raw
    except Exception:
        return ""


def _node_line(ts_node: Any) -> int:
    try:
        return ts_node.start_point[0] + 1
    except Exception:
        return 0


def _child_by_field(ts_node: Any, name: str) -> Any:
    try:
        return ts_node.child_by_field_name(name)
    except Exception:
        return None


def _named_children(ts_node: Any) -> list[Any]:
    try:
        return list(ts_node.named_children)
    except Exception:
        return []


class CFGBuilder:

    def __init__(
        self,
        site: HybridSite,
        func_node: Any,
        language: Language,
    ) -> None:
        self._site = site
        self._func_node = func_node
        self._lang = language
        self._next_id = 0

        self._cpg = FunctionCPG(site=site)
        self._label_map: dict[str, int] = {}
        self._pending_gotos: list[tuple[int, str]] = []

        exit_node = CPGNode(
            id=EXIT_NODE_ID,
            kind="EXIT",
            text="<exit>",
            line=0,
        )
        self._cpg.add_node(exit_node)


    def build(self) -> FunctionCPG:
        body = self._get_function_body()
        if body is None:
            return self._cpg

        stmts = self._block_children(body)
        self._process_statement_list(stmts, successor_id=EXIT_NODE_ID)

        self._resolve_gotos()
        return self._cpg

    def to_networkx(self) -> nx.DiGraph:
        g = nx.DiGraph()
        for nid, node in self._cpg.nodes.items():
            g.add_node(nid, kind=node.kind, text=node.text, line=node.line,
                        label=node.label.value, detail=node.detail)
        for edge in self._cpg.edges:
            if edge.edge_type.startswith("cfg"):
                g.add_edge(edge.src, edge.dst, edge_type=edge.edge_type)
        return g


    def _alloc_id(self) -> int:
        nid = self._next_id
        self._next_id += 1
        return nid

    def _make_node(self, ts_node: Any) -> CPGNode:
        nid = self._alloc_id()
        node = CPGNode(
            id=nid,
            kind=ts_node.type,
            text=_node_text(ts_node),
            line=_node_line(ts_node),
            ts_node=ts_node,
        )
        self._cpg.add_node(node)
        return node


    def _is_type(self, ts_node: Any, table: dict[Language, set[str]]) -> bool:
        return ts_node.type in table.get(self._lang, set())

    def _get_function_body(self) -> Any:
        body = _child_by_field(self._func_node, "body")
        if body is not None:
            return body
        for child in _named_children(self._func_node):
            if child.type in _COMPOUND_TYPES.get(self._lang, set()):
                return child
        return self._func_node

    def _block_children(self, block_node: Any) -> list[Any]:
        children = _named_children(block_node)
        return [c for c in children if c.type not in ("{", "}", "(", ")")]


    def _process_statement_list(
        self,
        stmts: list[Any],
        successor_id: int,
    ) -> Optional[int]:
        if not stmts:
            return None

        node_ids: list[int] = []
        is_terminator: list[bool] = []

        for stmt in stmts:
            nid, term = self._process_single_statement(stmt, successor_id)
            node_ids.append(nid)
            is_terminator.append(term)

        for i in range(len(node_ids) - 1):
            if not is_terminator[i]:
                self._cpg.add_edge(node_ids[i], node_ids[i + 1], "cfg")

        if not is_terminator[-1]:
            self._cpg.add_edge(node_ids[-1], successor_id, "cfg")

        return node_ids[0] if node_ids else None


    def _process_single_statement(
        self,
        ts_node: Any,
        successor_id: int,
    ) -> tuple[int, bool]:
        if self._is_type(ts_node, _IF_TYPES):
            return self._process_if(ts_node, successor_id)

        if self._is_type(ts_node, _GOTO_TYPES):
            return self._process_goto(ts_node)

        if self._is_type(ts_node, _RETURN_TYPES):
            return self._process_return(ts_node)

        if self._is_type(ts_node, _THROW_TYPES):
            return self._process_throw(ts_node)

        if self._is_type(ts_node, _LOOP_TYPES):
            return self._process_loop(ts_node, successor_id)

        if self._is_type(ts_node, _SWITCH_TYPES):
            return self._process_switch(ts_node, successor_id)

        if self._is_type(ts_node, _LABEL_TYPES):
            return self._process_labeled(ts_node, successor_id)

        if self._is_type(ts_node, _TRY_TYPES):
            return self._process_try(ts_node, successor_id)

        if self._lang == Language.RUST and self._contains_try_operator(ts_node):
            return self._process_rust_try(ts_node, successor_id)

        if ts_node.type in ("let_declaration", "short_var_declaration",
                            "assignment_expression", "assignment_statement"):
            inner_if = self._find_inner_if(ts_node)
            if inner_if is not None:
                return self._process_if(inner_if, successor_id)

        node = self._make_node(ts_node)
        return node.id, False

    def _find_inner_if(self, ts_node: Any) -> Any:
        for child in _named_children(ts_node):
            if self._is_type(child, _IF_TYPES):
                return child
            for grandchild in _named_children(child):
                if self._is_type(grandchild, _IF_TYPES):
                    return grandchild
        return None


    def _process_if(
        self, ts_node: Any, successor_id: int
    ) -> tuple[int, bool]:
        node = self._make_node(ts_node)

        then_block = _child_by_field(ts_node, "consequence") or _child_by_field(ts_node, "body")
        then_entry = None
        if then_block is not None:
            stmts = self._block_children(then_block)
            then_entry = self._process_statement_list(stmts, successor_id)

        else_block = _child_by_field(ts_node, "alternative")
        else_entry = None
        if else_block is not None:
            if self._is_type(else_block, _IF_TYPES):
                else_entry, _ = self._process_single_statement(
                    else_block, successor_id
                )
            else:
                stmts = self._block_children(else_block)
                else_entry = self._process_statement_list(stmts, successor_id)

        true_target = then_entry if then_entry is not None else successor_id
        false_target = else_entry if else_entry is not None else successor_id

        self._cpg.add_edge(node.id, true_target, "cfg_true")
        self._cpg.add_edge(node.id, false_target, "cfg_false")

        return node.id, True

    def _process_goto(self, ts_node: Any) -> tuple[int, bool]:
        node = self._make_node(ts_node)
        label_name = self._extract_goto_label(ts_node)
        if label_name:
            self._pending_gotos.append((node.id, label_name))
        return node.id, True

    def _process_return(self, ts_node: Any) -> tuple[int, bool]:
        node = self._make_node(ts_node)
        self._cpg.add_edge(node.id, EXIT_NODE_ID, "cfg")
        return node.id, True

    def _process_throw(self, ts_node: Any) -> tuple[int, bool]:
        node = self._make_node(ts_node)
        self._cpg.add_edge(node.id, EXIT_NODE_ID, "cfg")
        return node.id, True

    def _process_loop(
        self, ts_node: Any, successor_id: int
    ) -> tuple[int, bool]:
        node = self._make_node(ts_node)

        body = _child_by_field(ts_node, "body")
        if body is not None:
            stmts = self._block_children(body)
            body_entry = self._process_statement_list(stmts, node.id)
            if body_entry is not None:
                self._cpg.add_edge(node.id, body_entry, "cfg_true")

        self._cpg.add_edge(node.id, successor_id, "cfg_false")
        return node.id, True

    def _process_switch(
        self, ts_node: Any, successor_id: int
    ) -> tuple[int, bool]:
        node = self._make_node(ts_node)

        body = _child_by_field(ts_node, "body")
        if body is None:
            body = ts_node

        for child in _named_children(body):
            if child.type in (
                "switch_case", "case_statement", "default_case",
                "switch_default", "match_arm",
                "expression_case", "default_case", "type_case",
            ):
                case_stmts = self._block_children(child)
                case_entry = self._process_statement_list(
                    case_stmts, successor_id
                )
                if case_entry is not None:
                    self._cpg.add_edge(node.id, case_entry, "cfg")

        return node.id, True

    def _process_labeled(
        self, ts_node: Any, successor_id: int
    ) -> tuple[int, bool]:
        node = self._make_node(ts_node)

        label_child = _child_by_field(ts_node, "label")
        if label_child is not None:
            label_name = _node_text(label_child)
        else:
            children = _named_children(ts_node)
            label_name = _node_text(children[0]) if children else ""

        label_name = label_name.strip().rstrip(":")
        if label_name:
            self._label_map[label_name] = node.id

        inner = _child_by_field(ts_node, "body")
        if inner is None:
            children = _named_children(ts_node)
            for c in reversed(children):
                if c.type not in ("identifier", "statement_identifier"):
                    inner = c
                    break

        if inner is not None:
            inner_id, inner_term = self._process_single_statement(
                inner, successor_id
            )
            self._cpg.add_edge(node.id, inner_id, "cfg")
            return node.id, inner_term

        return node.id, False

    def _process_try(
        self, ts_node: Any, successor_id: int
    ) -> tuple[int, bool]:
        node = self._make_node(ts_node)

        body = _child_by_field(ts_node, "body")
        if body is not None:
            stmts = self._block_children(body)
            body_entry = self._process_statement_list(stmts, successor_id)
            if body_entry is not None:
                self._cpg.add_edge(node.id, body_entry, "cfg")

        for child in _named_children(ts_node):
            if child.type in ("catch_clause", "catch_declaration"):
                catch_body = _child_by_field(child, "body")
                if catch_body is not None:
                    catch_stmts = self._block_children(catch_body)
                    catch_entry = self._process_statement_list(
                        catch_stmts, successor_id
                    )
                    if catch_entry is not None:
                        self._cpg.add_edge(node.id, catch_entry, "cfg")

        for child in _named_children(ts_node):
            if child.type == "finally_clause":
                fin_body = _child_by_field(child, "body")
                if fin_body is not None:
                    fin_stmts = self._block_children(fin_body)
                    self._process_statement_list(fin_stmts, successor_id)

        return node.id, True


    def _contains_try_operator(self, ts_node: Any) -> bool:
        if ts_node.type == "try_expression":
            return True
        for child in _named_children(ts_node):
            if self._contains_try_operator(child):
                return True
        return False

    def _process_rust_try(
        self, ts_node: Any, successor_id: int
    ) -> tuple[int, bool]:
        node = self._make_node(ts_node)
        self._cpg.add_edge(node.id, EXIT_NODE_ID, "cfg_false")
        return node.id, False


    def _extract_goto_label(self, ts_node: Any) -> str:
        label_child = _child_by_field(ts_node, "label")
        if label_child is not None:
            return _node_text(label_child).strip()
        for child in _named_children(ts_node):
            if child.type in ("identifier", "statement_identifier"):
                return _node_text(child).strip()
        text = _node_text(ts_node)
        parts = text.replace(";", "").split()
        if len(parts) >= 2:
            return parts[1].strip()
        return ""

    def _resolve_gotos(self) -> None:
        for goto_id, label_name in self._pending_gotos:
            target_id = self._label_map.get(label_name)
            if target_id is not None:
                self._cpg.add_edge(goto_id, target_id, "cfg")
            else:
                self._cpg.add_edge(goto_id, EXIT_NODE_ID, "cfg")


def build_cfg(
    site: HybridSite,
    func_node: Any,
    language: Language,
) -> FunctionCPG:
    builder = CFGBuilder(site, func_node, language)
    return builder.build()


def build_cfg_networkx(
    site: HybridSite,
    func_node: Any,
    language: Language,
) -> tuple[FunctionCPG, nx.DiGraph]:
    builder = CFGBuilder(site, func_node, language)
    cpg = builder.build()
    graph = builder.to_networkx()
    return cpg, graph
