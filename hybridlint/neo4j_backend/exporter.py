"""Export a FunctionCPG to Neo4j.

Creates :CPGNode nodes and :CFG / :AST_CHILD / :DATAFLOW relationships
that mirror the in-memory FunctionCPG structure so that Cypher queries
can operate on exactly the same graph the NetworkX checkers see.
"""
from __future__ import annotations

from hybridlint.cpg.models import FunctionCPG, CPGNode
from hybridlint.neo4j_backend.driver import Neo4jConnection

# Maximum nodes per UNWIND batch (avoids overly large transactions)
_BATCH = 500


def export_cpg(conn: Neo4jConnection, cpg: FunctionCPG) -> None:
    """Write *cpg* into Neo4j.  Caller should ``conn.clear()`` first."""
    _create_nodes(conn, cpg)
    _create_edges(conn, cpg)


# ── nodes ────────────────────────────────────────────────────��──────

def _create_nodes(conn: Neo4jConnection, cpg: FunctionCPG) -> None:
    rows = []
    for n in cpg.nodes.values():
        rows.append({
            "node_id": n.id,
            "kind": n.kind,
            "text": n.text[:2000],          # cap very long texts
            "line": n.line,
            "op_label": "NONE",              # set later by labeler
            "val_label": "NONE",
            "component": 0,
            "detail": n.detail or "",
            "file_path": cpg.site.file_path,
            "function_name": cpg.site.function_name,
        })

    for i in range(0, len(rows), _BATCH):
        batch = rows[i : i + _BATCH]
        conn.run_write(
            """
            UNWIND $rows AS r
            CREATE (n:CPGNode {
                node_id:       r.node_id,
                kind:          r.kind,
                text:          r.text,
                line:          r.line,
                op_label:      r.op_label,
                val_label:     r.val_label,
                component:     r.component,
                detail:        r.detail,
                file_path:     r.file_path,
                function_name: r.function_name
            })
            """,
            rows=batch,
        )


# ── edges ───────────────────────────────────────────────────────────

def _create_edges(conn: Neo4jConnection, cpg: FunctionCPG) -> None:
    cfg_rows = []
    ast_rows = []
    df_rows = []

    for e in cpg.edges:
        row = {"src": e.src, "dst": e.dst}
        if e.edge_type.startswith("cfg"):
            row["etype"] = e.edge_type       # "cfg", "cfg_true", "cfg_false"
            cfg_rows.append(row)
        elif e.edge_type == "ast_child":
            ast_rows.append(row)
        elif e.edge_type == "dataflow":
            df_rows.append(row)

    _batch_create_edges(conn, cfg_rows, "CFG", has_type=True)
    _batch_create_edges(conn, ast_rows, "AST_CHILD")
    _batch_create_edges(conn, df_rows,  "DATAFLOW")


def _batch_create_edges(
    conn: Neo4jConnection,
    rows: list[dict],
    rel_type: str,
    has_type: bool = False,
) -> None:
    if not rows:
        return

    if has_type:
        cypher = f"""
            UNWIND $rows AS r
            MATCH (a:CPGNode {{node_id: r.src}})
            MATCH (b:CPGNode {{node_id: r.dst}})
            CREATE (a)-[:{rel_type} {{type: r.etype}}]->(b)
        """
    else:
        cypher = f"""
            UNWIND $rows AS r
            MATCH (a:CPGNode {{node_id: r.src}})
            MATCH (b:CPGNode {{node_id: r.dst}})
            CREATE (a)-[:{rel_type}]->(b)
        """

    for i in range(0, len(rows), _BATCH):
        conn.run_write(cypher, rows=rows[i : i + _BATCH])
