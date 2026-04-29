"""S1-S6 vulnerability detection via Cypher pattern-matching queries.

Each rule is expressed as one or more Cypher ``MATCH`` patterns that run
against the labeled CPG stored in Neo4j.  Returns ``Finding`` objects
identical to those produced by the Python/NetworkX checkers.

Cypher label schema (set by ``labeler_cypher.py``):

    (:CPGNode {
        node_id, kind, text, line,
        op_label  ∈ {PARAM, KEYGEN, ENCAP, DECAP, COMBINER,
                     ZEROIZE, ERROR_CHECK, ERROR_HANDLER, RNG, CONFIG, NONE},
        val_label ∈ {ek_1, ek_2, dk_1, dk_2, c_1, c_2, K_1, K_2, K, NONE},
        component ∈ {0, 1, 2},
        detail, file_path, function_name
    })

Relationship types:  :CFG  :AST_CHILD  :DATAFLOW
"""
from __future__ import annotations

from hybridlint.cpg.models import Finding, Severity, Verdict
from hybridlint.neo4j_backend.driver import Neo4jConnection

# ═══════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════

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

# Expected binding: group → (classical_kw, pqc_kw)
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


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def run_all_checks(conn: Neo4jConnection) -> list[Finding]:
    """Execute every S-rule against the current Neo4j graph."""
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


# ═══════════════════════════════════════════════════════════════════════
# S1-1  Parameter Mismatch
# ═══════════════════════════════════════════════════════════════════════

def check_s1_1(conn: Neo4jConnection) -> list[Finding]:
    """PARAM node contains hybrid group ID but dataflow successors
    lack the expected classical or PQC component keywords."""
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


# ═══════════════════════════════════════════════════════════════════════
# S2-1  Weak Combiner
# ═══════════════════════════════════════════════════════════════════════

def check_s2_1(conn: Neo4jConnection) -> list[Finding]:
    """COMBINER node whose detail is 'xor', confirmed by a dataflow
    predecessor that is a crypto operation."""
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


# ═══════════════════════════════════════════════════════════════════════
# S2-2  Missing Context Binding
# ═══════════════════════════════════════════════════════════════════════

def check_s2_2(conn: Neo4jConnection) -> list[Finding]:
    """COMBINER node whose dataflow predecessors do NOT contain
    ciphertext / public-key / label / algorithm-ID references."""
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


# ═══════════════════════════════════════════════════════════════════════
# S3-1  Key Domain Violation
# ═══════════════════════════════════════════════════════════════════════

def check_s3_1(conn: Neo4jConnection) -> list[Finding]:
    """KEYGEN(comp=1) output reaches both a hybrid context AND a
    standalone classical context via dataflow."""
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


# ═══════════════════════════════════════════════════════════════════════
# S3-2  Shared Seed Without KDF
# ═══════════════════════════════════════════════════════════════════════

def check_s3_2(conn: Neo4jConnection) -> list[Finding]:
    """Single RNG node reaches BOTH component-1 and component-2 crypto
    ops via dataflow without an intervening COMBINER(kdf)."""
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


# ═══════════════════════════════════════════════════════════════════════
# S4-1  Undestroyed Intermediate on Half-Success (Encaps)
# ═══════════════════════════════════════════════════════════════════════

def check_s4_1(conn: Neo4jConnection) -> list[Finding]:
    """ENCAP(comp=1) followed by ENCAP(comp=2).  Error check after
    ENCAP_2 leads to EXIT without a ZEROIZE on the CFG path."""
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


# ═══════════════════════════════════════════════════════════════════════
# S4-2  Undestroyed Intermediate on Completion (Encaps)
# ═══════════════════════════════════════════════════════════════════════

def check_s4_2(conn: Neo4jConnection) -> list[Finding]:
    """Both ENCAP_1 and ENCAP_2 complete, but no ZEROIZE node exists
    between them or after the second one."""
    rows = conn.run("""
        MATCH (e1:CPGNode {op_label: 'ENCAP', component: 1}),
              (e2:CPGNode {op_label: 'ENCAP', component: 2})
        WHERE e1.line < e2.line
          AND e1.file_path = e2.file_path
        AND NOT EXISTS {
            MATCH (z:CPGNode {op_label: 'ZEROIZE'})
            WHERE z.file_path = e1.file_path
              AND z.function_name = e1.function_name
              AND (z.line > e1.line AND z.line < e2.line)
        }
        AND NOT EXISTS {
            MATCH (z:CPGNode {op_label: 'ZEROIZE'})
            WHERE z.file_path = e1.file_path
              AND z.function_name = e1.function_name
              AND z.line > e2.line
        }
        RETURN DISTINCT
               e1.line          AS line,
               e1.file_path     AS file_path,
               e1.function_name AS function_name,
               e2.line          AS e2_line
    """)
    return [
        _make(r, "S4-2", Verdict.FAIL, Severity.HIGH,
              f"No zeroize between ENCAP_1 (L{r['line']}) and "
              f"ENCAP_2 (L{r['e2_line']}) or after.")
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════
# S5-1  Undestroyed Intermediate on Half-Success (Decaps)
# ═══════════════════════════════════════════════════════════════════════

def check_s5_1(conn: Neo4jConnection) -> list[Finding]:
    """Same pattern as S4-1 but for DECAP nodes."""
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


# ═══════════════════════════════════════════════════════════════════════
# S5-2  Undestroyed Intermediate on Completion (Decaps)
# ═══════════════════════════════════════════════════════════════════════

def check_s5_2(conn: Neo4jConnection) -> list[Finding]:
    """Same pattern as S4-2 but for DECAP nodes."""
    rows = conn.run("""
        MATCH (d1:CPGNode {op_label: 'DECAP', component: 1}),
              (d2:CPGNode {op_label: 'DECAP', component: 2})
        WHERE d1.line < d2.line
          AND d1.file_path = d2.file_path
        AND NOT EXISTS {
            MATCH (z:CPGNode {op_label: 'ZEROIZE'})
            WHERE z.file_path = d1.file_path
              AND z.function_name = d1.function_name
              AND (z.line > d1.line AND z.line < d2.line)
        }
        AND NOT EXISTS {
            MATCH (z:CPGNode {op_label: 'ZEROIZE'})
            WHERE z.file_path = d1.file_path
              AND z.function_name = d1.function_name
              AND z.line > d2.line
        }
        RETURN DISTINCT
               d1.line          AS line,
               d1.file_path     AS file_path,
               d1.function_name AS function_name,
               d2.line          AS d2_line
    """)
    return [
        _make(r, "S5-2", Verdict.FAIL, Severity.HIGH,
              f"No zeroize between DECAP_1 (L{r['line']}) and "
              f"DECAP_2 (L{r['d2_line']}) or after.")
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════
# S6-1  Silent Single-KEM Fallback
# ═══════════════════════════════════════════════════════════════════════

def check_s6_1(conn: Neo4jConnection) -> list[Finding]:
    """ERROR_CHECK after PQC ENCAP/DECAP whose CFG successors do NOT
    contain an abort / error-return pattern → may silently fall back."""
    rows = conn.run("""
        MATCH (pqc:CPGNode {component: 2}),
              (ec:CPGNode {op_label: 'ERROR_CHECK'})
        WHERE pqc.op_label IN ['ENCAP', 'DECAP']
          AND ec.line >= pqc.line
          AND ec.file_path = pqc.file_path
        WITH ec
        MATCH (ec)-[:CFG]->(handler:CPGNode)
        WHERE NOT handler.op_label = 'ERROR_HANDLER'
          AND NOT handler.text =~ '(?i).*(goto\\s+\\w+|return\\s+(-?\\d+|err|error|NULL|false|FAILURE)|abort\\s*\\(|exit\\s*\\(|panic\\s*\\().*'
        RETURN DISTINCT
               ec.line          AS line,
               ec.file_path     AS file_path,
               ec.function_name AS function_name,
               handler.text     AS handler_text
    """)
    return [
        _make(r, "S6-1", Verdict.FAIL, Severity.HIGH,
              f"PQC error check at L{r['line']}: handler does not abort. "
              f"May silently fall back to classical-only key.")
        for r in rows
    ]
