from __future__ import annotations

from hkemlint.neo4j_backend.driver import Neo4jConnection


_ZEROIZE_KW = [
    "ForceZero", "OPENSSL_cleanse", "explicit_bzero", "memset_s",
    "SecureZeroMemory", "OPENSSL_clear_free", "sodium_memzero",
    "wipememory", "_gnutls_free_key_datum", "zeroize", ".zeroize()",
    "ExplicitBzero", "Arrays.fill",
]

_COMBINER_KDF_KW = [
    "HKDF", "hkdf", "HKDF_expand", "hkdf_expand", "HKDF_extract",
    "hkdf_extract", "tls13_generate_handshake_secret", "ssh_digest_buffer",
    "SHA3", "sha3", "SHA256", "sha256", "SHA512", "sha512",
    "HMAC", "hmac", "SHAKE256", "shake256", "BLAKE2", "blake2b",
    "labeledExtract", "labeledExpand", "PairSplitPRF",
]

_COMBINER_XOR_KW = [
    "xor_bytes", "XOR", "xor", "xor_assign",
]

_COMBINER_CONCAT_KW = [
    "memcpy", "memmove", "XMEMCPY", "append",
    "extend_from_slice", "CBB_add_bytes", "sshbuf_put",
]

_RNG_KW = [
    "RAND_bytes", "RAND_priv_bytes", "arc4random_buf",
    "getrandom", "getentropy", "wc_RNG_GenerateBlock",
    "OQS_randombytes", "OsRng", "thread_rng",
    "io.ReadFull", "rand.Read", "SecureRandom",
]

_GROUP_CONFIG_KW = [
    "supported_groups", "supportedCurves", "CurvePreferences",
    "defaultCurvePreferences", "kDefaultGroups",
    "kem_preferences", "kem_groups", "key_share",
    "KeyShareEntry", "keyShares",
]

_HYBRID_GROUP_KW = [
    "SSL_GROUP_X25519_MLKEM768", "SSL_GROUP_SECP256R1_MLKEM768",
    "SSL_GROUP_SECP384R1_MLKEM1024", "SSL_GROUP_X25519_KYBER768",
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "X25519Kyber768", "X25519Kyber768Draft00",
]


_DECAP_PQC_KW = [
    "MLKEM768_decap", "MLKEM1024_decap", "OQS_KEM_decaps",
    "wc_KyberDecapsulate", "Decapsulate(", "decapsulate(",
    "kem_decaps", "KEM_decapsulate",
]

_ENCAP_PQC_KW = [
    "MLKEM768_encap", "MLKEM1024_encap", "OQS_KEM_encaps",
    "wc_KyberEncapsulate", "Encapsulate(", "encapsulate(",
    "kem_encaps", "KEM_encapsulate",
]

_KEYGEN_PQC_KW = [
    "MLKEM768_generate_key", "MLKEM1024_generate_key",
    "OQS_KEM_keypair", "wc_KyberKey_MakeKey",
    "TLSX_KeyShare_GenPqcKey", "ml_kem_keypair", "kem_keypairs",
]

_KEYGEN_CLASSICAL_KW = [
    "X25519_keypair", "X25519_public_from_private",
    "kexc25519_keygen", "EVP_PKEY_keygen",
    "wc_ecc_make_key", "EccMakeKey",
    "TLSX_KeyShare_GenEccKey", "TLSX_KeyShare_GenX25519Key",
]

_ENCAP_CLASSICAL_KW = [
    "EVP_PKEY_derive", "ECDH_compute_key",
    "wc_curve25519_shared_secret", "wc_ecc_shared_secret",
    "kexc25519_shared_key", "TLSX_KeyShare_ProcessEcc",
    "TLSX_KeyShare_ProcessX25519", "calculate_agreement",
]

_PQC_GENERIC_KW = [
    "mlkem", "MLKEM", "kyber", "Kyber", "OQS_KEM", "pqc", "PQC",
]

_CLASSICAL_GENERIC_KW = [
    "x25519", "X25519", "ecdh", "ECDH", "curve25519", "Curve25519",
    "secp256r1", "secp384r1", "sntrup761",
]


_ERR_CHECK_PATTERNS = [
    "ret != 0", "ret < 0", "ret <= 0", "ret == 0",
    "== NULL", "!= SSL_SUCCESS", "!= WOLFSSL_SUCCESS",
    "!= OQS_SUCCESS", "err != nil", "ON_ERR_SET_GOTO", "ON_ERR_GOTO",
]

_ERR_HANDLER_PATTERNS = [
    "goto ", "return -", "return err", "return error",
    "return FAILURE", "return WOLFSSL_FAILURE", "return NULL",
    "abort(", "exit(", "panic(",
]


def _any_contains(prop: str, keywords: list[str]) -> str:
    escaped = [kw.replace("\\", "\\\\").replace("'", "\\'") for kw in keywords]
    kw_list = ", ".join(f"'{k}'" for k in escaped)
    return f"any(kw IN [{kw_list}] WHERE n.{prop} CONTAINS kw)"


def label_nodes_cypher(conn: Neo4jConnection) -> None:
    _pass1_op_labels(conn)
    _pass2_val_labels(conn)


def _pass1_op_labels(conn: Neo4jConnection) -> None:

    stmts: list[str] = []

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _ZEROIZE_KW)}
        SET n.op_label = 'ZEROIZE'
    """)

    for pat in _ERR_CHECK_PATTERNS:
        escaped = pat.replace("'", "\\'")
        stmts.append(f"""
            MATCH (n:CPGNode)
            WHERE n.op_label = 'NONE'
              AND (n.kind IN ['if_statement', 'if_expression',
                              'if_let_expression', 'expression_statement'])
              AND n.text CONTAINS '{escaped}'
            SET n.op_label = 'ERROR_CHECK'
        """)

    for pat in _ERR_HANDLER_PATTERNS:
        escaped = pat.replace("'", "\\'")
        stmts.append(f"""
            MATCH (n:CPGNode)
            WHERE n.op_label = 'NONE'
              AND n.text CONTAINS '{escaped}'
            SET n.op_label = 'ERROR_HANDLER'
        """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _RNG_KW)}
        SET n.op_label = 'RNG'
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _COMBINER_KDF_KW)}
        SET n.op_label = 'COMBINER', n.detail = 'kdf'
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _COMBINER_XOR_KW)}
        SET n.op_label = 'COMBINER', n.detail = 'xor'
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _COMBINER_CONCAT_KW)}
        SET n.op_label = 'COMBINER', n.detail = 'concat'
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _GROUP_CONFIG_KW)}
        SET n.op_label = 'CONFIG'
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _HYBRID_GROUP_KW)}
        SET n.op_label = 'PARAM'
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _DECAP_PQC_KW)}
        SET n.op_label = 'DECAP', n.component = 2
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _ENCAP_PQC_KW)}
        SET n.op_label = 'ENCAP', n.component = 2
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _KEYGEN_PQC_KW)}
        SET n.op_label = 'KEYGEN', n.component = 2
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _KEYGEN_CLASSICAL_KW)}
        SET n.op_label = 'KEYGEN', n.component = 1
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _ENCAP_CLASSICAL_KW)}
        SET n.op_label = 'ENCAP', n.component = 1
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _PQC_GENERIC_KW)}
          AND (n.text CONTAINS '(' OR n.text CONTAINS '=')
        SET n.op_label = CASE
            WHEN n.text =~ '(?i).*decap.*'       THEN 'DECAP'
            WHEN n.text =~ '(?i).*encap.*'       THEN 'ENCAP'
            WHEN n.text =~ '(?i).*keygen.*'      THEN 'KEYGEN'
            WHEN n.text =~ '(?i).*generate_key.*' THEN 'KEYGEN'
            WHEN n.text =~ '(?i).*keypair.*'     THEN 'KEYGEN'
            ELSE 'ENCAP'
          END,
          n.component = 2
    """)

    stmts.append(f"""
        MATCH (n:CPGNode)
        WHERE n.op_label = 'NONE'
          AND {_any_contains('text', _CLASSICAL_GENERIC_KW)}
          AND (n.text CONTAINS '(' OR n.text CONTAINS '=')
        SET n.op_label = CASE
            WHEN n.text =~ '(?i).*keygen.*'       THEN 'KEYGEN'
            WHEN n.text =~ '(?i).*generate_key.*'  THEN 'KEYGEN'
            WHEN n.text =~ '(?i).*keypair.*'      THEN 'KEYGEN'
            WHEN n.text =~ '(?i).*shared_secret.*' THEN 'ENCAP'
            WHEN n.text =~ '(?i).*derive.*'        THEN 'ENCAP'
            ELSE 'ENCAP'
          END,
          n.component = 1
    """)

    for stmt in stmts:
        conn.run_write(stmt)


def _pass2_val_labels(conn: Neo4jConnection) -> None:

    stmts: list[str] = []


    stmts.append("""
        MATCH (n:CPGNode {op_label: 'COMBINER'})
        SET n.val_label = 'K'
    """)
    stmts.append("""
        MATCH (n:CPGNode)
        WHERE n.op_label IN ['ENCAP', 'DECAP'] AND n.component = 1
        SET n.val_label = 'K_1'
    """)
    stmts.append("""
        MATCH (n:CPGNode)
        WHERE n.op_label IN ['ENCAP', 'DECAP'] AND n.component = 2
        SET n.val_label = 'K_2'
    """)
    stmts.append("""
        MATCH (n:CPGNode {op_label: 'KEYGEN', component: 1})
        SET n.val_label = 'dk_1'
    """)
    stmts.append("""
        MATCH (n:CPGNode {op_label: 'KEYGEN', component: 2})
        SET n.val_label = 'dk_2'
    """)


    _val_name_rules = [
        ("K",   ["combined_secret", "hybrid_secret", "final_secret",
                 "master_secret", "preMasterSecret", "handshake_secret"]),
        ("K_1", ["x25519_ss", "ecdh_secret", "classical_secret",
                 "dh_shared", "x25519_shared", "ecc_shared", "sntrup_ss"]),
        ("K_2", ["mlkem_ss", "kem_secret", "pqc_secret", "kyber_ss",
                 "mlkem_shared", "kyber_shared", "brace_shared"]),
        ("ek_1", ["x25519_pub", "ecdh_pub", "classical_pub",
                  "our_ephemeral_pub"]),
        ("ek_2", ["mlkem_ek", "kyber_pub", "pqc_pub", "kem_pub",
                  "encapsulation_key", "brace_ek"]),
        ("dk_1", ["x25519_priv", "ecdh_priv", "classical_priv"]),
        ("dk_2", ["mlkem_dk", "kyber_priv", "pqc_priv",
                  "decapsulation_key", "brace_dk"]),
        ("c_1",  ["x25519_ct", "ecdh_ct", "classical_ct", "dh_public"]),
        ("c_2",  ["mlkem_ct", "kyber_ct", "pqc_ct", "kem_ct",
                  "kem_ciphertext", "brace_ct"]),
    ]

    for val, keywords in _val_name_rules:
        escaped = [k.replace("'", "\\'") for k in keywords]
        kw_list = ", ".join(f"'{k}'" for k in escaped)
        stmts.append(f"""
            MATCH (n:CPGNode)
            WHERE n.val_label = 'NONE'
              AND any(kw IN [{kw_list}] WHERE n.text CONTAINS kw)
            SET n.val_label = '{val}'
        """)


    stmts.append("""
        MATCH (src:CPGNode)-[:DATAFLOW]->(dst:CPGNode)
        WHERE src.component = 1
          AND dst.val_label = 'NONE'
          AND dst.text =~ '(?i).*(?:secret|shared|ss|key).*'
        SET dst.val_label = 'K_1', dst.component = 1
    """)
    stmts.append("""
        MATCH (src:CPGNode)-[:DATAFLOW]->(dst:CPGNode)
        WHERE src.component = 2
          AND dst.val_label = 'NONE'
          AND dst.text =~ '(?i).*(?:secret|shared|ss|key).*'
        SET dst.val_label = 'K_2', dst.component = 2
    """)

    for stmt in stmts:
        conn.run_write(stmt)
