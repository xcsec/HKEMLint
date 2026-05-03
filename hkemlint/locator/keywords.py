

CLASSICAL_KEYWORDS = {
    "x25519", "X25519", "curve25519", "Curve25519", "CURVE25519",
    "X25519_keypair", "X25519_public_from_private",
    "kexc25519_keygen",
    "ecdh", "ECDH", "ecdhe", "ECDHE",
    "ECDH_compute_key", "EVP_PKEY_derive",
    "secp256r1", "secp384r1", "secp521r1",
    "P256", "P384", "P521", "p256", "p384",
    "NID_X9_62_prime256v1", "NID_secp384r1",
    "CurveP256", "CurveP384",
    "WOLFSSL_ECC_X25519", "WOLFSSL_ECC_X448",
    "DiffieHellman", "diffie_hellman",
    "calculate_agreement", "key_agreement",
    "our_base_private_key", "our_identity_key",
    "TLSX_KeyShare_ProcessEcc", "TLSX_KeyShare_ProcessX25519",
    "TLSX_KeyShare_ProcessX448", "TLSX_KeyShare_GenEccKey",
    "TLSX_KeyShare_GenX25519Key", "EccMakeKey",
    "wc_ecc_shared_secret", "wc_curve25519_shared_secret",
    "SSL_GROUP_X25519", "SSL_GROUP_SECP256R1", "SSL_GROUP_SECP384R1",
    "sntrup761",
}

PQC_KEYWORDS = {
    "mlkem", "MLKEM", "ML_KEM", "ml_kem", "MlKem",
    "MLKEM768", "MLKEM1024", "mlkem768", "mlkem1024",
    "kyber", "Kyber", "KYBER",
    "Kyber768", "Kyber1024",
    "kem_encaps", "kem_decaps",
    "KEM_encapsulate", "KEM_decapsulate",
    "MLKEM768_encap", "MLKEM768_decap",
    "MLKEM1024_encap", "MLKEM1024_decap",
    "wc_KyberEncapsulate", "wc_KyberDecapsulate",
    "OQS_KEM_encaps", "OQS_KEM_decaps", "OQS_KEM",
    "libcrux_ml_kem",
    "TLSX_KeyShare_ProcessPqcClient", "TLSX_KeyShare_GenPqcKey",
    "wc_KyberKey_SharedSecretSize", "wc_KyberKey_CipherTextSize",
    "ml_kem", "MlKem1024", "MlKem768",
    "hqc", "hqc256", "hqc_keypair",
    "decapsulate", "Decapsulate", "encapsulate",
    "ml_kem_keypair", "kem_keypairs",
    "SplitPRF", "sharedSecrets",
    "combiner.New",
    "TLSX_KeyShare_ProcessPqcClient", "TLSX_KeyShare_GenPqcKey",
    "wc_KyberKey_SharedSecretSize", "wc_KyberKey_CipherTextSize",
    "pqc", "PQC", "post_quantum",
    "PQXDH",
    "xwing", "XWing", "XWING", "X_Wing",
}

HYBRID_DIRECT = {
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "X25519Kyber768", "X25519Kyber768Draft00",
    "SSL_GROUP_X25519_MLKEM768", "SSL_GROUP_SECP256R1_MLKEM768",
    "SSL_GROUP_SECP384R1_MLKEM1024",
    "SSL_GROUP_X25519_KYBER768",
    "x25519_mlkem", "hybrid_kem", "hyb_kem", "HybridKeyShare",
    "ProcessPqcHybrid", "PqcHybrid", "pqc_hybrid",
    "WOLFSSL_NAMED_GROUP_IS_PQC_HYBRID",
    "mlkem768x25519", "sntrup761x25519",
    "kex_kem_mlkem768x25519",
    "combiner.New", "SplitPRF",
    "sharedSecrets",
    "HybridKeyExchange", "complete_component", "ActiveHybrid",
    "kDefaultGroups", "defaultCurvePreferences",
}

GROUP_CONFIG_KEYWORDS = {
    "supported_groups", "supportedCurves", "CurvePreferences",
    "defaultCurvePreferences", "kDefaultGroups",
    "kem_preferences", "kem_groups",
    "key_share", "KeyShareEntry", "keyShares",
    "HelloRetryRequest", "hello_retry",
}


ZEROIZE_FUNCTIONS = {
    "ForceZero", "OPENSSL_cleanse", "explicit_bzero", "memset_s",
    "SecureZeroMemory", "OPENSSL_clear_free", "sodium_memzero",
    "wipememory", "secure_zero_memory", "cc_clear",
    "_gnutls_free_key_datum",
    "zeroize", ".zeroize()",
    "ExplicitBzero",
    "Arrays.fill",
}

INSECURE_FREE_FUNCTIONS = {
    "_gnutls_free_datum",
}

RUST_ZEROIZE_MARKERS = {
    "Zeroize", "ZeroizeOnDrop", "Zeroizing<", "zeroize_on_drop",
}

RUST_ZEROIZE_MARKERS = {
    "Zeroize", "ZeroizeOnDrop", "Zeroizing<", "zeroize_on_drop",
}

FREE_FUNCTIONS = {
    "free", "OPENSSL_free", "EVP_PKEY_free", "EVP_PKEY_CTX_free",
    "XFREE", "BN_free", "BN_clear_free",
    "_gnutls_free_datum",
}

COMBINER_KDF = {
    "HKDF", "hkdf", "HKDF_expand", "hkdf_expand",
    "HKDF_extract", "hkdf_extract",
    "tls13_generate_handshake_secret",
    "ssh_digest_buffer",
    "SHA3", "sha3", "SHA256", "sha256", "SHA512", "sha512",
    "HMAC", "hmac",
    "SHAKE256", "shake256",
    "BLAKE2", "blake2b",
    "labeledExtract", "labeledExpand",
    "PairSplitPRF",
}

COMBINER_CONCAT = {
    "memcpy", "memmove", "XMEMCPY",
    "append",
    "extend_from_slice",
    "copy",
}

COMBINER_XOR = {
    "xor_bytes", "XOR", "xor",
    "xor_assign",
    "^ ",
}

RNG_FUNCTIONS = {
    "RAND_bytes", "RAND_priv_bytes", "arc4random_buf",
    "getrandom", "getentropy",
    "wc_RNG_GenerateBlock",
    "OQS_randombytes",
    "OsRng", "thread_rng", "getrandom",
    "crypto/rand", "io.ReadFull", "rand.Read",
    "SecureRandom",
}

C_ERROR_PATTERNS = [
    "goto ",
    "ON_ERR_SET_GOTO",
    "ON_ERR_GOTO",
]

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
