from __future__ import annotations

from hkemlint.cpg.models import Finding, Severity, Verdict
from hkemlint.neo4j_backend.driver import Neo4jConnection


_HYBRID_GROUPS = [
    "SSL_GROUP_X25519_MLKEM768", "SSL_GROUP_SECP256R1_MLKEM768",
    "SSL_GROUP_SECP384R1_MLKEM1024", "SSL_GROUP_X25519_KYBER768",
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "X25519Kyber768", "X25519Kyber768Draft00",
]

_CLASSICAL_GROUPS = [
    "SSL_GROUP_X25519", "SSL_GROUP_SECP256R1", "SSL_GROUP_SECP384R1",
    "X25519", "CurveP256", "CurveP384",
]

_BINDINGS = {
    "X25519MLKEM768":                (["X25519", "x25519", "Curve25519"], ["MLKEM768", "mlkem768", "Kyber768"]),
    "SSL_GROUP_X25519_MLKEM768":     (["X25519", "x25519", "Curve25519"], ["MLKEM768", "mlkem768", "Kyber768"]),
    "SecP256r1MLKEM768":             (["P-256", "P256", "secp256r1"],     ["MLKEM768", "mlkem768", "Kyber768"]),
    "SSL_GROUP_SECP256R1_MLKEM768":  (["P-256", "P256", "secp256r1"],     ["MLKEM768", "mlkem768", "Kyber768"]),
    "SecP384r1MLKEM1024":            (["P-384", "P384", "secp384r1"],     ["MLKEM1024", "mlkem1024", "Kyber1024"]),
    "SSL_GROUP_SECP384R1_MLKEM1024": (["P-384", "P384", "secp384r1"],     ["MLKEM1024", "mlkem1024", "Kyber1024"]),
}


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


def _make(row: dict, rule_id: str, verdict: Verdict,
          severity: Severity, evidence: str) -> Finding:
    return Finding(
        project=_project_name(row.get("file_path", "")),
        file_path=row.get("file_path", ""),
        function_name=row.get("function_name", ""),
        rule_id=rule_id,
        verdict=verdict,
        severity=severity,
        evidence=evidence,
        lines=[row["line"]] if "line" in row else [],
    )


def run_all_checks(conn: Neo4jConnection) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_s1_1(conn))
    findings.extend(check_s2_1(conn))
    findings.extend(check_s2_2(conn))
    findings.extend(check_s3_1(conn))
    findings.extend(check_s3_2(conn))
    findings.extend(check_s4_1(conn))
    findings.extend(check_s4_2(conn))
    findings.extend(check_s5_1(conn))
    findings.extend(check_s5_2(conn))
    findings.extend(check_s6_1(conn))
    return findings


def check_s1_1(conn: Neo4jConnection) -> list[Finding]:
    findings: list[Finding] = []

    for group_id, (c_kws, p_kws) in _BINDINGS.items():
        c_any = " OR ".join(f"succ.text CONTAINS '{k}'" for k in c_kws)
        p_any = " OR ".join(f"succ.text CONTAINS '{k}'" for k in p_kws)

        rows = conn.run(f"""
            MATCH (p:CPGNode {{op_label: 'PARAM'}})
            WHERE p.text CONTAINS '{group_id}'
            OPTIONAL MATCH (p)-[:DATAFLOW*1..8]->(succ:CPGNode)
            WITH p,
                 COLLECT(succ) AS succs,
                 any(s IN COLLECT(succ) WHERE {c_any}) AS has_c,
                 any(s IN COLLECT(succ) WHERE {p_any}) AS has_p
            WHERE NOT (has_c AND has_p)
            RETURN p.line       AS line,
                   p.file_path  AS file_path,
                   p.function_name AS function_name,
                   has_c, has_p
        """)

        for r in rows:
            missing = []
            if not r["has_c"]:
                missing.append("classical")
            if not r["has_p"]:
                missing.append("PQC")
            findings.append(_make(
                r, "S1-1", Verdict.FAIL, Severity.HIGH,
                f"Parameter binding for {group_id} missing "
                f"{' and '.join(missing)} (Cypher dataflow).",
            ))

    return findings


def check_s2_1(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (c:CPGNode {op_label: 'COMBINER'})
        WHERE c.detail = 'xor'
        AND EXISTS {
            MATCH (src:CPGNode)-[:DATAFLOW*1..6]->(c)
            WHERE src.op_label IN ['ENCAP', 'DECAP', 'KEYGEN']
               OR src.val_label IN ['K_1', 'K_2']
        }
        RETURN c.line          AS line,
               c.text          AS text,
               c.file_path     AS file_path,
               c.function_name AS function_name
    """)
    return [
        _make(r, "S2-1", Verdict.FAIL, Severity.HIGH,
              f"XOR combiner at L{r['line']}: "
              f"`{r['text'][:80]}`. Not IND-CCA preserving.")
        for r in rows
    ]


def check_s2_2(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (c:CPGNode {op_label: 'COMBINER'})
        WHERE EXISTS {
            MATCH (src:CPGNode)-[:DATAFLOW*1..6]->(c)
            WHERE src.op_label IN ['ENCAP', 'DECAP', 'KEYGEN']
               OR src.val_label IN ['K_1', 'K_2']
        }
        OPTIONAL MATCH (pred:CPGNode)-[:DATAFLOW*1..8]->(c)
        WITH c, COLLECT(pred.text) + [c.text] AS texts
        WITH c,
             any(t IN texts WHERE t =~ '(?i).*(ciphertext|ct_|_ct|mlkem_ct|kem_ciphertext).*')  AS has_ct,
             any(t IN texts WHERE t =~ '(?i).*(public_key|pk_|_pk|encapsulation_key|peer_pub).*') AS has_pk,
             any(t IN texts WHERE t =~ '(?i).*(label|domain|separator|suite_id|context_string).*') AS has_label,
             any(t IN texts WHERE t =~ '(?i).*(alg_?id|algorithm|oid|suite|group_id|kem_id).*')   AS has_algid
        WHERE NOT (has_ct AND has_pk AND has_label AND has_algid)
        RETURN c.line          AS line,
               c.detail        AS detail,
               c.file_path     AS file_path,
               c.function_name AS function_name,
               has_ct, has_pk, has_label, has_algid
    """)
    findings: list[Finding] = []
    for r in rows:
        missing = []
        if not r["has_ct"]:
            missing.append("ciphertext")
        if not r["has_pk"]:
            missing.append("public_key")
        if not r["has_label"]:
            missing.append("label")
        if not r["has_algid"]:
            missing.append("algorithm_id")
        if len(missing) >= 3:
            findings.append(_make(
                r, "S2-2", Verdict.FAIL, Severity.MEDIUM,
                f"Combiner at L{r['line']} ({r['detail']}) missing "
                f"context: {', '.join(missing)}.",
            ))
        elif missing:
            findings.append(_make(
                r, "S2-2", Verdict.UNCERTAIN, Severity.MEDIUM,
                f"Combiner at L{r['line']} missing {', '.join(missing)}.",
            ))
    return findings


def check_s3_1(conn: Neo4jConnection) -> list[Finding]:
    hg_any = " OR ".join(f"h.text CONTAINS '{g}'" for g in _HYBRID_GROUPS)
    cg_any = " OR ".join(f"s.text CONTAINS '{g}'" for g in _CLASSICAL_GROUPS)
    hg_not = " AND ".join(f"NOT s.text CONTAINS '{g}'" for g in _HYBRID_GROUPS)

    rows = conn.run(f"""
        MATCH (kg:CPGNode {{op_label: 'KEYGEN', component: 1}})
              -[:DATAFLOW*1..10]->(h:CPGNode)
        WHERE h.op_label = 'COMBINER' OR ({hg_any})
        WITH kg
        MATCH (kg)-[:DATAFLOW*1..10]->(s:CPGNode)
        WHERE ({cg_any}) AND ({hg_not})
        RETURN DISTINCT
               kg.line          AS line,
               kg.file_path     AS file_path,
               kg.function_name AS function_name
    """)
    return [
        _make(r, "S3-1", Verdict.FAIL, Severity.HIGH,
              f"KEYGEN at L{r['line']} feeds both hybrid and "
              f"standalone contexts (key domain violation).")
        for r in rows
    ]


def check_s3_2(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (rng:CPGNode {op_label: 'RNG'})
              -[:DATAFLOW*1..6]->(c1:CPGNode {component: 1})
        WHERE c1.op_label IN ['KEYGEN', 'ENCAP']
        WITH rng
        MATCH (rng)-[:DATAFLOW*1..6]->(c2:CPGNode {component: 2})
        WHERE c2.op_label IN ['KEYGEN', 'ENCAP']
        AND NOT EXISTS {
            MATCH (rng)-[:DATAFLOW*1..3]->(kdf:CPGNode {op_label: 'COMBINER'})
                  -[:DATAFLOW*1..3]->(c2)
            WHERE kdf.detail = 'kdf'
        }
        RETURN DISTINCT
               rng.line          AS line,
               rng.file_path     AS file_path,
               rng.function_name AS function_name
    """)
    return [
        _make(r, "S3-2", Verdict.FAIL, Severity.HIGH,
              f"RNG at L{r['line']} feeds both components "
              f"without KDF domain separation.")
        for r in rows
    ]


def check_s4_1(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (e1:CPGNode {op_label: 'ENCAP', component: 1}),
              (e2:CPGNode {op_label: 'ENCAP', component: 2}),
              (ec:CPGNode {op_label: 'ERROR_CHECK'})
        WHERE e1.line < e2.line
          AND ec.line >= e2.line
          AND e1.file_path = e2.file_path
          AND e2.file_path = ec.file_path
        AND NOT EXISTS {
            MATCH (ec)-[:CFG*1..25]->(z:CPGNode {op_label: 'ZEROIZE'})
        }
        RETURN DISTINCT
               ec.line          AS line,
               ec.file_path     AS file_path,
               ec.function_name AS function_name,
               e1.line          AS e1_line,
               e2.line          AS e2_line
    """)
    return [
        _make(r, "S4-1", Verdict.FAIL, Severity.HIGH,
              f"ENCAP_2 error at L{r['line']}: K_1 from ENCAP_1 "
              f"(L{r['e1_line']}) not zeroized on error path.")
        for r in rows
    ]


def check_s4_2(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (e1:CPGNode {op_label: 'ENCAP', component: 1}),
              (e2:CPGNode {op_label: 'ENCAP', component: 2}),
              (c:CPGNode  {op_label: 'COMBINER'})
        WHERE e1.line < e2.line
          AND e1.file_path = e2.file_path
          AND c.file_path  = e1.file_path
          AND c.line > e2.line
        WITH c
        MATCH (c)-[:CFG*1..25]->(ret:CPGNode)
        WHERE ret.kind = 'return_statement' OR ret.node_id = -1
        AND NOT EXISTS {
            MATCH (c)-[:CFG*1..25]->(z:CPGNode {op_label: 'ZEROIZE'})-[:CFG*0..25]->(ret)
        }
        RETURN DISTINCT
               c.line          AS line,
               c.file_path     AS file_path,
               c.function_name AS function_name
    """)
    return [
        _make(r, "S4-2", Verdict.FAIL, Severity.HIGH,
              f"COMBINER at L{r['line']} → return: component secrets "
              f"not zeroized on CFG path to exit.")
        for r in rows
    ]


def check_s5_1(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (d1:CPGNode {op_label: 'DECAP', component: 1}),
              (d2:CPGNode {op_label: 'DECAP', component: 2}),
              (ec:CPGNode {op_label: 'ERROR_CHECK'})
        WHERE d1.line < d2.line
          AND ec.line >= d2.line
          AND d1.file_path = d2.file_path
          AND d2.file_path = ec.file_path
        AND NOT EXISTS {
            MATCH (ec)-[:CFG*1..25]->(z:CPGNode {op_label: 'ZEROIZE'})
        }
        RETURN DISTINCT
               ec.line          AS line,
               ec.file_path     AS file_path,
               ec.function_name AS function_name,
               d1.line          AS d1_line,
               d2.line          AS d2_line
    """)
    return [
        _make(r, "S5-1", Verdict.FAIL, Severity.HIGH,
              f"DECAP_2 error at L{r['line']}: K_1 from DECAP_1 "
              f"(L{r['d1_line']}) not zeroized on error path.")
        for r in rows
    ]


def check_s5_2(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (d1:CPGNode {op_label: 'DECAP', component: 1}),
              (d2:CPGNode {op_label: 'DECAP', component: 2}),
              (c:CPGNode  {op_label: 'COMBINER'})
        WHERE d1.line < d2.line
          AND d1.file_path = d2.file_path
          AND c.file_path  = d1.file_path
          AND c.line > d2.line
        WITH c
        MATCH (c)-[:CFG*1..25]->(ret:CPGNode)
        WHERE ret.kind = 'return_statement' OR ret.node_id = -1
        AND NOT EXISTS {
            MATCH (c)-[:CFG*1..25]->(z:CPGNode {op_label: 'ZEROIZE'})-[:CFG*0..25]->(ret)
        }
        RETURN DISTINCT
               c.line          AS line,
               c.file_path     AS file_path,
               c.function_name AS function_name
    """)
    return [
        _make(r, "S5-2", Verdict.FAIL, Severity.HIGH,
              f"COMBINER at L{r['line']} → return: component secrets "
              f"not zeroized on CFG path to exit.")
        for r in rows
    ]


def check_s6_1(conn: Neo4jConnection) -> list[Finding]:
    rows = conn.run("""
        MATCH (c:CPGNode {op_label: 'COMBINER'})
        OPTIONAL MATCH (pred:CPGNode)-[:DATAFLOW*1..6]->(c)
        WITH c,
             COLLECT(pred) AS preds,
             any(p IN COLLECT(pred) WHERE p.component = 1
                 OR p.val_label = 'K_1'
                 OR p.text =~ '(?i).*(x25519|ecdh|curve25519|classical|dh_shared).*') AS has_ss1,
             any(p IN COLLECT(pred) WHERE p.component = 2
                 OR p.val_label = 'K_2'
                 OR p.text =~ '(?i).*(mlkem|kyber|kem_secret|pqc|kem_shared).*') AS has_ss2
        WHERE NOT (has_ss1 AND has_ss2)
        AND EXISTS {
            MATCH (c)-[:CFG*1..25]->(ret:CPGNode)
            WHERE ret.kind = 'return_statement' OR ret.node_id = -1
        }
        RETURN c.line          AS line,
               c.file_path     AS file_path,
               c.function_name AS function_name,
               has_ss1, has_ss2
    """)
    findings: list[Finding] = []
    for r in rows:
        missing = []
        if not r["has_ss1"]:
            missing.append("ss_1 (classical)")
        if not r["has_ss2"]:
            missing.append("ss_2 (PQC)")
        findings.append(_make(
            r, "S6-1", Verdict.FAIL, Severity.HIGH,
            f"COMBINER at L{r['line']} does not consume both component "
            f"secrets. Missing: {', '.join(missing)}. "
            f"Hybrid KEM degrades to single-component."))
    return findings
