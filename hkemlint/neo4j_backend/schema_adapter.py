from __future__ import annotations

from hkemlint.neo4j_backend.driver import Neo4jConnection


def project_schema(conn: Neo4jConnection) -> None:
    _cleanup(conn)
    _project_nodes(conn)
    _project_cfg_edges(conn)
    _project_dataflow_edges(conn)
    _project_ast_edges(conn)
    _create_exit_node(conn)


def _cleanup(conn: Neo4jConnection) -> None:
    conn.run_write("MATCH (n:CPGNode) DETACH DELETE n")


def _project_nodes(conn: Neo4jConnection) -> None:
    conn.run_write("""
        MATCH (n:Node)
        WHERE n.code IS NOT NULL
          AND n.startLine IS NOT NULL
        CREATE (c:CPGNode {
            node_id:       id(n),
            fraunhofer_id: id(n),
            kind:          CASE
                WHEN n:CallExpression            THEN 'call_expression'
                WHEN n:MemberCallExpression      THEN 'call_expression'
                WHEN n:ConstructExpression        THEN 'call_expression'
                WHEN n:BinaryOperator            THEN 'binary_operator'
                WHEN n:UnaryOperator             THEN 'unary_operator'
                WHEN n:Reference                 THEN 'reference'
                WHEN n:DeclaredReferenceExpression THEN 'reference'
                WHEN n:Literal                   THEN 'literal'
                WHEN n:IfStatement               THEN 'if_statement'
                WHEN n:ForStatement              THEN 'for_statement'
                WHEN n:WhileStatement            THEN 'while_statement'
                WHEN n:DoStatement               THEN 'do_statement'
                WHEN n:SwitchStatement           THEN 'switch_statement'
                WHEN n:ReturnStatement           THEN 'return_statement'
                WHEN n:TryStatement              THEN 'try_statement'
                WHEN n:CatchClause               THEN 'catch_clause'
                WHEN n:ThrowExpression            THEN 'throw_expression'
                WHEN n:FunctionDeclaration       THEN 'function_definition'
                WHEN n:MethodDeclaration         THEN 'function_definition'
                WHEN n:VariableDeclaration       THEN 'declaration'
                WHEN n:FieldDeclaration          THEN 'declaration'
                WHEN n:RecordDeclaration         THEN 'struct_specifier'
                WHEN n:CompoundStatement         THEN 'compound_statement'
                WHEN n:DeclarationStatement      THEN 'declaration'
                WHEN n:Expression                THEN 'expression_statement'
                WHEN n:Statement                 THEN 'expression_statement'
                ELSE 'other'
            END,
            text:          LEFT(n.code, 2000),
            line:          n.startLine,
            op_label:      'NONE',
            val_label:     'NONE',
            component:     0,
            detail:        COALESCE(n.name, ''),
            file_path:     COALESCE(n.file, ''),
            function_name: ''
        })
    """)

    conn.run_write("""
        MATCH (fn:FunctionDeclaration)-[:AST*1..10]->(child:Node)
        WHERE child.code IS NOT NULL
        WITH child, fn
        MATCH (c:CPGNode {fraunhofer_id: id(child)})
        SET c.function_name = COALESCE(fn.name, '')
    """)

    conn.run_write("""
        MATCH (fn:FunctionDeclaration)
        WHERE fn.code IS NOT NULL
        WITH fn
        MATCH (c:CPGNode {fraunhofer_id: id(fn)})
        SET c.function_name = COALESCE(fn.name, '')
    """)


def _project_cfg_edges(conn: Neo4jConnection) -> None:
    conn.run_write("""
        MATCH (a:Node)-[e:EOG]->(b:Node)
        WHERE a.code IS NOT NULL AND b.code IS NOT NULL
        WITH a, b, e
        MATCH (ca:CPGNode {fraunhofer_id: id(a)})
        MATCH (cb:CPGNode {fraunhofer_id: id(b)})
        CREATE (ca)-[:CFG {type: 'cfg'}]->(cb)
    """)


def _project_dataflow_edges(conn: Neo4jConnection) -> None:
    conn.run_write("""
        MATCH (a:Node)-[:DFG]->(b:Node)
        WHERE a.code IS NOT NULL AND b.code IS NOT NULL
        WITH a, b
        MATCH (ca:CPGNode {fraunhofer_id: id(a)})
        MATCH (cb:CPGNode {fraunhofer_id: id(b)})
        CREATE (ca)-[:DATAFLOW]->(cb)
    """)


def _project_ast_edges(conn: Neo4jConnection) -> None:
    conn.run_write("""
        MATCH (a:Node)-[:AST]->(b:Node)
        WHERE a.code IS NOT NULL AND b.code IS NOT NULL
        WITH a, b
        MATCH (ca:CPGNode {fraunhofer_id: id(a)})
        MATCH (cb:CPGNode {fraunhofer_id: id(b)})
        CREATE (ca)-[:AST_CHILD]->(cb)
    """)


def _create_exit_node(conn: Neo4jConnection) -> None:
    conn.run_write("""
        CREATE (:CPGNode {
            node_id:       -1,
            fraunhofer_id: -1,
            kind:          'EXIT',
            text:          '',
            line:          -1,
            op_label:      'NONE',
            val_label:     'NONE',
            component:     0,
            detail:        '',
            file_path:     '',
            function_name: ''
        })
    """)

    conn.run_write("""
        MATCH (r:CPGNode)
        WHERE r.kind = 'return_statement'
        MATCH (exit:CPGNode {node_id: -1})
        CREATE (r)-[:CFG {type: 'cfg'}]->(exit)
    """)
