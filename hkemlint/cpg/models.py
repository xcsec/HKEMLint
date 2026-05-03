from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


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


class OpLabel(str, Enum):
    PARAM = "PARAM"
    KEYGEN = "KEYGEN"
    ENCAP = "ENCAP"
    DECAP = "DECAP"
    COMBINER = "COMBINER"
    ZEROIZE = "ZEROIZE"
    ERROR_CHECK = "ERROR_CHECK"
    ERROR_HANDLER = "ERROR_HANDLER"
    RNG = "RNG"
    CONFIG = "CONFIG"
    NONE = "NONE"


class ValLabel(str, Enum):
    ek_1 = "ek_1"
    ek_2 = "ek_2"
    dk_1 = "dk_1"
    dk_2 = "dk_2"
    c_1 = "c_1"
    c_2 = "c_2"
    K_1 = "K_1"
    K_2 = "K_2"
    K = "K"
    NONE = "NONE"


class CryptoLabel(str, Enum):
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


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNCERTAIN = "UNCERTAIN"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class HybridSite:
    file_path: str
    language: Language
    function_name: str
    start_line: int
    end_line: int
    body_text: str
    match_strategy: str
    matched_keywords: list[str] = field(default_factory=list)
    ts_node: Any = None

    @property
    def site_id(self) -> str:
        return f"{self.file_path}::{self.function_name}"


@dataclass
class CPGNode:
    id: int
    kind: str
    text: str
    line: int
    op_label: OpLabel = OpLabel.NONE
    val_label: ValLabel = ValLabel.NONE
    component: int = 0
    detail: str = ""
    ts_node: Any = None
    label: CryptoLabel = CryptoLabel.OTHER


@dataclass
class CPGEdge:
    src: int
    dst: int
    edge_type: str


@dataclass
class FunctionCPG:
    site: HybridSite
    nodes: dict[int, CPGNode] = field(default_factory=dict)
    edges: list[CPGEdge] = field(default_factory=list)


    def add_node(self, node: CPGNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, src: int, dst: int, edge_type: str) -> None:
        self.edges.append(CPGEdge(src, dst, edge_type))


    def get_nodes_by_op(self, op: OpLabel) -> list[CPGNode]:
        return [n for n in self.nodes.values() if n.op_label == op]

    def get_nodes_by_val(self, val: ValLabel) -> list[CPGNode]:
        return [n for n in self.nodes.values() if n.val_label == val]

    def get_nodes_by_component(self, comp: int) -> list[CPGNode]:
        return [n for n in self.nodes.values() if n.component == comp]


    def get_nodes_by_label(self, label: CryptoLabel) -> list[CPGNode]:
        return [n for n in self.nodes.values() if n.label == label]


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


@dataclass
class Finding:
    project: str
    file_path: str
    function_name: str
    rule_id: str
    verdict: Verdict
    severity: Severity
    evidence: str
    lines: list[int] = field(default_factory=list)
    sp: str = ""
    sub_property: str = ""
