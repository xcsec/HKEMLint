"""Keyword dictionaries for hybrid KEM code identification and semantic labeling."""

# =============================================================================
# Phase 1: Site Location Keywords
# =============================================================================

# Group A: Classical crypto identifiers
CLASSICAL_KEYWORDS = {
    # X25519 / Curve25519
    "x25519", "X25519", "curve25519", "Curve25519", "CURVE25519",
    "X25519_keypair", "X25519_public_from_private",
    "kexc25519_keygen",
    # ECDH / ECDHE
    "ecdh", "ECDH", "ecdhe", "ECDHE",
    "ECDH_compute_key", "EVP_PKEY_derive",
    # Named curves
    "secp256r1", "secp384r1", "secp521r1",
    "P256", "P384", "P521", "p256", "p384",
    "NID_X9_62_prime256v1", "NID_secp384r1",
    "CurveP256", "CurveP384",
    "WOLFSSL_ECC_X25519", "WOLFSSL_ECC_X448",
    # DH / Key Agreement
    "DiffieHellman", "diffie_hellman",
    "calculate_agreement", "key_agreement",
    "our_base_private_key", "our_identity_key",
    # wolfSSL ECDH functions
    "TLSX_KeyShare_ProcessEcc", "TLSX_KeyShare_ProcessX25519",
    "TLSX_KeyShare_ProcessX448", "TLSX_KeyShare_GenEccKey",
    "TLSX_KeyShare_GenX25519Key", "EccMakeKey",
    "wc_ecc_shared_secret", "wc_curve25519_shared_secret",
    # BoringSSL/AWS-LC
    "SSL_GROUP_X25519", "SSL_GROUP_SECP256R1", "SSL_GROUP_SECP384R1",
    # SSH hybrid classical component
    "sntrup761",
}

# Group B: PQC KEM identifiers
PQC_KEYWORDS = {
    # ML-KEM / Kyber
    "mlkem", "MLKEM", "ML_KEM", "ml_kem", "MlKem",
    "MLKEM768", "MLKEM1024", "mlkem768", "mlkem1024",
    "kyber", "Kyber", "KYBER",
    "Kyber768", "Kyber1024",
    # KEM operations
    "kem_encaps", "kem_decaps",
    "KEM_encapsulate", "KEM_decapsulate",
    "MLKEM768_encap", "MLKEM768_decap",
    "MLKEM1024_encap", "MLKEM1024_decap",
    "wc_KyberEncapsulate", "wc_KyberDecapsulate",
    "OQS_KEM_encaps", "OQS_KEM_decaps", "OQS_KEM",
    "libcrux_ml_kem",
    # wolfSSL PQC
    "TLSX_KeyShare_ProcessPqcClient", "TLSX_KeyShare_GenPqcKey",
    "wc_KyberKey_SharedSecretSize", "wc_KyberKey_CipherTextSize",
    # Rust ML-KEM/HQC (Mullvad)
    "ml_kem", "MlKem1024", "MlKem768",
    "hqc", "hqc256", "hqc_keypair",
    "decapsulate", "Decapsulate", "encapsulate",
    "ml_kem_keypair", "kem_keypairs",
    # Go combiner (HPQC/katzenpost)
    "SplitPRF", "sharedSecrets",
    "combiner.New",
    # wolfSSL PQC
    "TLSX_KeyShare_ProcessPqcClient", "TLSX_KeyShare_GenPqcKey",
    "wc_KyberKey_SharedSecretSize", "wc_KyberKey_CipherTextSize",
    # General PQC
    "pqc", "PQC", "post_quantum",
    # Signal protocol
    "PQXDH",
    # X-Wing
    "xwing", "XWing", "XWING", "X_Wing",
}

# Group C: Direct hybrid identifiers (match alone, no co-location needed)
HYBRID_DIRECT = {
    # TLS named groups
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "X25519Kyber768", "X25519Kyber768Draft00",
    "SSL_GROUP_X25519_MLKEM768", "SSL_GROUP_SECP256R1_MLKEM768",
    "SSL_GROUP_SECP384R1_MLKEM1024",
    "SSL_GROUP_X25519_KYBER768",
    # Implementation patterns
    "x25519_mlkem", "hybrid_kem", "hyb_kem", "HybridKeyShare",
    "ProcessPqcHybrid", "PqcHybrid", "pqc_hybrid",
    "WOLFSSL_NAMED_GROUP_IS_PQC_HYBRID",
    # SSH hybrid
    "mlkem768x25519", "sntrup761x25519",
    "kex_kem_mlkem768x25519",
    # Go KEM combiner (HPQC/katzenpost)
    "combiner.New", "SplitPRF",
    "sharedSecrets",
    # Rust hybrid key exchange traits
    "HybridKeyExchange", "complete_component", "ActiveHybrid",
    # Default group config (SP4)
    "kDefaultGroups", "defaultCurvePreferences",
}

# Group D: SP4-specific -- group negotiation and config
GROUP_CONFIG_KEYWORDS = {
    "supported_groups", "supportedCurves", "CurvePreferences",
    "defaultCurvePreferences", "kDefaultGroups",
    "kem_preferences", "kem_groups",
    "key_share", "KeyShareEntry", "keyShares",
    "HelloRetryRequest", "hello_retry",
}

# =============================================================================
# Phase 3: Semantic Labeling Dictionaries (per-language where needed)
# =============================================================================

# Zeroize functions (SP2)
ZEROIZE_FUNCTIONS = {
    # C / C++
    "ForceZero", "OPENSSL_cleanse", "explicit_bzero", "memset_s",
    "SecureZeroMemory", "OPENSSL_clear_free", "sodium_memzero",
    "wipememory", "secure_zero_memory", "cc_clear",
    # GnuTLS
    "_gnutls_free_key_datum",  # secure free (zeroizes then frees)
    # Rust
    "zeroize", ".zeroize()",
    # Go
    "ExplicitBzero",
    # Java
    "Arrays.fill",
}

# GnuTLS: insecure free that should be secure (SP2 — B3 pattern)
INSECURE_FREE_FUNCTIONS = {
    "_gnutls_free_datum",  # frees WITHOUT zeroizing — insecure for key material
}

# Rust: types that should implement Zeroize but don't (SP2 — B6/B7 pattern)
RUST_ZEROIZE_MARKERS = {
    "Zeroize", "ZeroizeOnDrop", "Zeroizing<", "zeroize_on_drop",
}

# Rust-specific zeroize traits/derives
RUST_ZEROIZE_MARKERS = {
    "Zeroize", "ZeroizeOnDrop", "Zeroizing<", "zeroize_on_drop",
}

# Free-without-zeroize (SP2 -- potential violation)
FREE_FUNCTIONS = {
    "free", "OPENSSL_free", "EVP_PKEY_free", "EVP_PKEY_CTX_free",
    "XFREE", "BN_free", "BN_clear_free",
    # GnuTLS insecure free
    "_gnutls_free_datum",
}

# Combiner functions (SP1)
COMBINER_KDF = {
    "HKDF", "hkdf", "HKDF_expand", "hkdf_expand",
    "HKDF_extract", "hkdf_extract",
    "tls13_generate_handshake_secret",
    "ssh_digest_buffer",  # SSH hash-based combiner
    "SHA3", "sha3", "SHA256", "sha256", "SHA512", "sha512",
    "HMAC", "hmac",
    "SHAKE256", "shake256",
    "BLAKE2", "blake2b",
    "labeledExtract", "labeledExpand",
    "PairSplitPRF",  # HPQC combiner
}

COMBINER_CONCAT = {
    "memcpy", "memmove", "XMEMCPY",
    "append",  # Go
    "extend_from_slice",  # Rust
    "copy",  # Go built-in
}

COMBINER_XOR = {
    "xor_bytes", "XOR", "xor",
    "xor_assign",  # Mullvad
    "^ ",  # bitwise XOR in code
}

# RNG functions (SP3)
RNG_FUNCTIONS = {
    # C / C++
    "RAND_bytes", "RAND_priv_bytes", "arc4random_buf",
    "getrandom", "getentropy",
    "wc_RNG_GenerateBlock",
    "OQS_randombytes",
    # Rust
    "OsRng", "thread_rng", "getrandom",
    # Go
    "crypto/rand", "io.ReadFull", "rand.Read",
    # Java
    "SecureRandom",
}

# Error-handling patterns (SP2)
C_ERROR_PATTERNS = [
    "goto ",  # C goto error handling
    "ON_ERR_SET_GOTO",  # wolfSSL macro
    "ON_ERR_GOTO",
]

# Group classification (SP4)
HYBRID_GROUP_IDS = {
    "SSL_GROUP_X25519_MLKEM768", "SSL_GROUP_SECP256R1_MLKEM768",
    "SSL_GROUP_SECP384R1_MLKEM1024", "SSL_GROUP_X25519_KYBER768",
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "X25519Kyber768", "X25519Kyber768Draft00",
    "WOLFSSL_SECP256R1_MLKEM768", "WOLFSSL_X25519_MLKEM768",
}

CLASSICAL_GROUP_IDS = {
    "SSL_GROUP_X25519", "SSL_GROUP_SECP256R1", "SSL_GROUP_SECP384R1",
    "SSL_GROUP_SECP521R1",
    "X25519", "CurveP256", "CurveP384", "CurveP521",
    "WOLFSSL_ECC_X25519", "WOLFSSL_ECC_SECP256R1",
}
