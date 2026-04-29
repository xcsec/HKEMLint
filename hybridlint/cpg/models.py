"""Core data models for HybridLint.

Label taxonomy (from paper §4):
  Operation labels  R_op  = {PARAM, KEYGEN, ENCAP, DECAP, COMBINER}
  Value labels      R_val = {ek_1, ek_2, dk_1, dk_2, c_1, c_2, K_1, K_2, K}

Component index: 1 = classical (ECDH / X25519), 2 = PQC (ML-KEM / Kyber).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ── Language ────────────────────────────────────────────────────────────

class Language(str, Enum):
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    GO = "go"
    JAVA = "java"
    PYTHON = "python"


EXTENSION_TO_LANG = {
    ".c": Language.C, ".h": Language.C,
    ".cc": Language.CPP, ".cpp": Language.CPP, ".cxx": Language.CPP,
    ".hpp": Language.CPP, ".hh": Language.CPP,
    ".rs": Language.RUST,
    ".go": Language.GO,
    ".java": Language.JAVA,
    ".py": Language.PYTHON,
}


# ── Operation labels (R_op + auxiliary) ─────────────────────────────────

class OpLabel(str, Enum):
    """Operation labels for hybrid-KEM lifecycle steps."""
    # Core R_op
    PARAM = "PARAM"
    KEYGEN = "KEYGEN"
    ENCAP = "ENCAP"
    DECAP = "DECAP"
    COMBINER = "COMBINER"
    # Auxiliary (needed for graph queries but not in R_op)
    ZEROIZE = "ZEROIZE"
    ERROR_CHECK = "ERROR_CHECK"
    ERROR_HANDLER = "ERROR_HANDLER"
    RNG = "RNG"
    CONFIG = "CONFIG"
    NONE = "NONE"


# ── Value labels (R_val) ───────────────────────────────────────────────

class ValLabel(str, Enum):
    """Value labels for hybrid-KEM protocol objects."""
    ek_1 = "ek_1"   # classical encapsulation key (public)
    ek_2 = "ek_2"   # PQC encapsulation key (public)
    dk_1 = "dk_1"   # classical decapsulation key (private)
    dk_2 = "dk_2"   # PQC decapsulation key (private)
    c_1 = "c_1"     # classical ciphertext / DH public value
    c_2 = "c_2"     # PQC ciphertext
    K_1 = "K_1"     # classical component shared secret
    K_2 = "K_2"     # PQC component shared secret
    K = "K"          # combined / final shared secret
    NONE = "NONE"


# ── Backward-compatible CryptoLabel (alias for migration) ──────────────
# Kept so cpg_builder.py and other modules don't break during transition.

class CryptoLabel(str, Enum):
    """Legacy labels — use OpLabel + ValLabel for new code."""
    CLASSICAL_OP = "classical_op"
    PQC_OP = "pqc_op"
    SECRET_BUF = "secret_buf"
    EPHEMERAL_KEY = "ephemeral_key"
    COMBINER = "combiner"
    ZEROIZE = "zeroize"
    FREE_NO_ZERO = "free_no_zero"
    ERROR_CHECK = "error_check"
    ERROR_HANDLER = "error_handler"
    RNG_CALL = "rng_call"
    GROUP_CONFIG = "group_config"
    PARAM_CONST = "param_const"
    OTHER = "other"


# ── Verdict / Severity ─────────────────────────────────────────────────

class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNCERTAIN = "UNCERTAIN"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ── Data classes ───────────────────────────────────────────────────────

@dataclass
class HybridSite:
    """A function identified as containing hybrid KEM code."""
    file_path: str
    language: Language
    function_name: str
    start_line: int
    end_line: int
    body_text: str
    match_strategy: str   # "direct" | "colocation" | "config" | "callee"
    matched_keywords: list[str] = field(default_factory=list)
    ts_node: Any = None

    @property
    def site_id(self) -> str:
        return f"{self.file_path}::{self.function_name}"


@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    id: int
    kind: str          # tree-sitter node type
    text: str          # source code text
    line: int
    # ── New dual-label system ──
    op_label: OpLabel = OpLabel.NONE
    val_label: ValLabel = ValLabel.NONE
    component: int = 0   # 0=unknown, 1=classical, 2=PQC
    detail: str = ""
    ts_node: Any = None
    # ── Legacy label (kept for backward compat during transition) ──
    label: CryptoLabel = CryptoLabel.OTHER


@dataclass
class CPGEdge:
    """An edge in the Code Property Graph."""
    src: int
    dst: int
    edge_type: str   # "cfg", "cfg_true", "cfg_false", "ast_child", "dataflow"


@dataclass
class FunctionCPG:
    """CPG for a single hybrid function."""
    site: HybridSite
    nodes: dict[int, CPGNode] = field(default_factory=dict)
    edges: list[CPGEdge] = field(default_factory=list)

    # ── Mutation ────────────────────────────────────────────────────

    def add_node(self, node: CPGNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, src: int, dst: int, edge_type: str) -> None:
        self.edges.append(CPGEdge(src, dst, edge_type))

    # ── Query by new labels ─────────────────────────────────────────

    def get_nodes_by_op(self, op: OpLabel) -> list[CPGNode]:
        """Return nodes with a given operation label."""
        return [n for n in self.nodes.values() if n.op_label == op]

    def get_nodes_by_val(self, val: ValLabel) -> list[CPGNode]:
        """Return nodes with a given value label."""
        return [n for n in self.nodes.values() if n.val_label == val]

    def get_nodes_by_component(self, comp: int) -> list[CPGNode]:
        """Return nodes belonging to a specific component (1=classical, 2=PQC)."""
        return [n for n in self.nodes.values() if n.component == comp]

    # ── Query by legacy label (backward compat) ────────────────────

    def get_nodes_by_label(self, label: CryptoLabel) -> list[CPGNode]:
        return [n for n in self.nodes.values() if n.label == label]

    # ── CFG navigation ──────────────────────────────────────────────

    def get_cfg_successors(self, node_id: int) -> list[tuple[int, str]]:
        return [
            (e.dst, e.edge_type)
            for e in self.edges
            if e.src == node_id and e.edge_type.startswith("cfg")
        ]

    def get_cfg_predecessors(self, node_id: int) -> list[tuple[int, str]]:
        return [
            (e.src, e.edge_type)
            for e in self.edges
            if e.dst == node_id and e.edge_type.startswith("cfg")
        ]

    # ── Dataflow navigation ─────────────────────────────────────────

    def get_dataflow_successors(self, node_id: int,
                                 max_depth: int = 6) -> set[int]:
        from collections import deque
        visited: set[int] = set()
        queue = deque([(node_id, 0)])
        while queue:
            nid, depth = queue.popleft()
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            for e in self.edges:
                if e.src == nid and e.edge_type == "dataflow":
                    queue.append((e.dst, depth + 1))
        visited.discard(node_id)
        return visited

    def get_dataflow_predecessors(self, node_id: int,
                                   max_depth: int = 6) -> set[int]:
        from collections import deque
        visited: set[int] = set()
        queue = deque([(node_id, 0)])
        while queue:
            nid, depth = queue.popleft()
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            for e in self.edges:
                if e.dst == nid and e.edge_type == "dataflow":
                    queue.append((e.src, depth + 1))
        visited.discard(node_id)
        return visited

    def get_nodes_by_text(self, keyword: str) -> list[CPGNode]:
        return [n for n in self.nodes.values()
                if n.id != -1 and keyword in n.text]

    def dataflow_path_has_label(self, src_id: int, dst_id: int,
                                 op_label: OpLabel,
                                 max_depth: int = 8) -> bool:
        """Check if any node with given op_label sits on a dataflow path
        between src and dst."""
        from collections import deque
        visited: set[int] = set()
        queue = deque([(src_id, 0, False)])
        while queue:
            nid, depth, found = queue.popleft()
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            node = self.nodes.get(nid)
            if node and nid != src_id and node.op_label == op_label:
                found = True
            if nid == dst_id:
                return found
            for e in self.edges:
                if e.src == nid and e.edge_type == "dataflow":
                    queue.append((e.dst, depth + 1, found))
        return False


# ── Finding ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A security property violation or observation."""
    project: str
    file_path: str
    function_name: str
    rule_id: str          # "S1-1", "S2-1", …, "S6-1"
    verdict: Verdict
    severity: Severity
    evidence: str
    lines: list[int] = field(default_factory=list)
    # Legacy fields (kept for backward compat)
    sp: str = ""
    sub_property: str = ""
