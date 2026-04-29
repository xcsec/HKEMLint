"""SP3 -- Component Independence checker.

Uses CPG dataflow edges to verify randomness independence:

  SP3a: Trace RNG_CALL nodes via dataflow → do they feed BOTH classical
        and PQC components, or only one each?
  SP3b: If a single seed feeds both, check if a KDF/hash node sits on
        the dataflow path (domain separation).
"""
from __future__ import annotations

import re
from collections import deque

import networkx as nx

from hybridlint.cpg.models import (
    CPGNode,
    CryptoLabel,
    Finding,
    FunctionCPG,
    Severity,
    Verdict,
)
from hybridlint.checkers.base import BaseChecker
from hybridlint.locator.keywords import COMBINER_KDF

# Functions that internally generate fresh randomness (implicit RNG)
_IMPLICIT_RNG = re.compile(
    r"\b("
    r"kexc25519_keygen|X25519_keypair|"
    r"MLKEM768_generate_key|MLKEM1024_generate_key|"
    r"MLKEM768_encap|MLKEM1024_encap|"
    r"EVP_PKEY_keygen|wc_KyberKey_MakeKey|wc_KyberEncapsulate|"
    r"OQS_KEM_encaps|OQS_KEM_keypair|"
    r"crypto_kem_sntrup761_enc|crypto_kem_sntrup761_keypair|"
    r"libcrux_ml_kem_mlkem768_portable_generate_key_pair|"
    r"libcrux_ml_kem_mlkem768_portable_encapsulate|"
    r"GenerateKey|Encapsulate|generate_key|encapsulate"
    r")\s*\(",
)

# Skip decaps/dec functions (deterministic, no RNG needed)
_DECAPS_RE = re.compile(r"(decaps|decapsulate|_dec$|_dec[^a-z]|Decap)", re.IGNORECASE)

# Seed variable name patterns (for seed-split detection)
_SEED_VAR_RE = re.compile(r"\b\w*(?:seed|eseed|rnd|rand|entropy|ikm)\w*\b", re.IGNORECASE)

# Direct seed slicing patterns (no KDF)
_SEED_SLICE_RES = [
    # C: memcpy(dst, seed, 32) or copy(dst, seed[:32])
    re.compile(
        r"(?:memcpy|memmove|XMEMCPY|copy)\s*\([^,]+,\s*"
        r"(\w*(?:seed|eseed|rnd|rand|entropy|ikm)\w*)\s*(?:\[|,)",
        re.IGNORECASE,
    ),
    # Go: seed[:32] / seed[32:]
    re.compile(r"(\w*(?:seed|eseed|rnd|rand)\w*)\s*\[\s*\d*\s*:\s*\d*\s*\]", re.IGNORECASE),
    # Rust: seed[..32] / seed[32..]
    re.compile(r"(\w*(?:seed|eseed|rnd|rand)\w*)\s*\[\s*(?:\.\.|\d+\s*\.\.)", re.IGNORECASE),
]


def _project_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "hybrid_kem_projects" and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-2] if len(parts) >= 2 else "unknown"


class SP3IndependenceChecker(BaseChecker):
    """SP3: Check randomness independence using CPG dataflow graph queries."""

    def check(self, cpg: FunctionCPG) -> list[Finding]:
        # Skip decaps functions (deterministic, no randomness)
        if _DECAPS_RE.search(cpg.site.function_name):
            return []

        findings = []
        findings.extend(self._check_sp3a(cpg))
        findings.extend(self._check_sp3b(cpg))
        return findings

    # ── SP3a: independent CSPRNG per component ───────────────────

    def _check_sp3a(self, cpg: FunctionCPG) -> list[Finding]:
        """
        CPG dataflow query:
          1. Find all RNG_CALL nodes + implicit-RNG nodes
          2. For each, trace dataflow forward to see if it reaches
             CLASSICAL_OP, PQC_OP, or both
          3. If one RNG → both components without KDF: FAIL
             If separate RNG → separate components: PASS
        """
        project = _project_name(cpg.site.file_path)

        # Collect explicit RNG nodes
        rng_nodes = cpg.get_nodes_by_label(CryptoLabel.RNG_CALL)

        # Collect implicit RNG nodes (keygen/encaps that internally call RNG)
        implicit_rng = []
        for n in cpg.nodes.values():
            if n.id == -1 or n.label == CryptoLabel.RNG_CALL:
                continue
            if _IMPLICIT_RNG.search(n.text):
                implicit_rng.append(n)

        all_rng = rng_nodes + implicit_rng
        if not all_rng:
            return [self._finding(cpg, project, "SP3a", Verdict.UNCERTAIN,
                                  Severity.MEDIUM,
                                  "No RNG sources found; randomness may come from caller.")]

        # Quick check: if we have implicit RNG for BOTH classical and PQC,
        # they are independent by definition (each function generates its own)
        implicit_classical = [n for n in implicit_rng
                              if n.label == CryptoLabel.CLASSICAL_OP
                              or any(kw in n.text for kw in
                                     ("x25519", "X25519", "curve25519", "ecdh",
                                      "ECDH", "ecc", "sntrup"))]
        implicit_pqc = [n for n in implicit_rng
                        if n.label == CryptoLabel.PQC_OP
                        or any(kw in n.text for kw in
                               ("mlkem", "MLKEM", "kyber", "Kyber",
                                "kem_enc", "KEM_enc"))]
        if implicit_classical and implicit_pqc:
            return [self._finding(cpg, project, "SP3a", Verdict.PASS,
                                  Severity.LOW,
                                  f"Both components use functions with internal RNG "
                                  f"(classical: L{implicit_classical[0].line}, "
                                  f"PQC: L{implicit_pqc[0].line}).",
                                  [implicit_classical[0].line, implicit_pqc[0].line])]

        if len(all_rng) >= 2:
            # Check if they feed different component types via dataflow
            feeds = self._classify_rng_targets(cpg, all_rng)
            classical_sources = [r for r, (c, p) in feeds.items() if c and not p]
            pqc_sources = [r for r, (c, p) in feeds.items() if p and not c]
            both_sources = [r for r, (c, p) in feeds.items() if c and p]

            if classical_sources and pqc_sources and not both_sources:
                return [self._finding(cpg, project, "SP3a", Verdict.PASS,
                                      Severity.LOW,
                                      f"{len(all_rng)} independent RNG sources feed "
                                      f"separate components.",
                                      [n.line for n in all_rng])]

            if both_sources:
                src = cpg.nodes.get(both_sources[0])
                return [self._finding(cpg, project, "SP3a", Verdict.FAIL,
                                      Severity.HIGH,
                                      f"RNG at L{src.line if src else '?'} feeds BOTH "
                                      f"classical and PQC components via dataflow.",
                                      [src.line] if src else [])]

            # Multiple RNG but can't confirm separation
            return [self._finding(cpg, project, "SP3a", Verdict.PASS,
                                  Severity.LOW,
                                  f"{len(all_rng)} RNG sources found; "
                                  f"components likely use independent randomness.",
                                  [n.line for n in all_rng])]

        # Only 1 RNG source — check if it feeds both components
        single = all_rng[0]
        feeds = self._classify_rng_targets(cpg, [single])
        c, p = feeds.get(single.id, (False, False))
        if c and p:
            return [self._finding(cpg, project, "SP3a", Verdict.FAIL,
                                  Severity.HIGH,
                                  f"Single RNG at L{single.line} feeds both "
                                  f"classical and PQC via dataflow. "
                                  f"Check SP3b for domain separation.",
                                  [single.line])]
        return [self._finding(cpg, project, "SP3a", Verdict.UNCERTAIN,
                              Severity.MEDIUM,
                              f"Single RNG at L{single.line}; cannot confirm "
                              f"it feeds both components.",
                              [single.line])]

    def _classify_rng_targets(self, cpg: FunctionCPG,
                               rng_nodes: list[CPGNode]
                               ) -> dict[int, tuple[bool, bool]]:
        """For each RNG node, BFS dataflow forward (max 6 hops) and check
        if CLASSICAL_OP or PQC_OP is reachable."""
        # Build dataflow-only graph
        dfg = nx.DiGraph()
        for n in cpg.nodes.values():
            dfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type == "dataflow":
                dfg.add_edge(e.src, e.dst)

        result = {}
        for rng in rng_nodes:
            classical = False
            pqc = False
            visited = set()
            queue = deque([(rng.id, 0)])
            while queue:
                nid, depth = queue.popleft()
                if nid in visited or depth > 6:
                    continue
                visited.add(nid)
                node = cpg.nodes.get(nid)
                if node and nid != rng.id:
                    if node.label == CryptoLabel.CLASSICAL_OP:
                        classical = True
                    elif node.label == CryptoLabel.PQC_OP:
                        pqc = True
                if nid in dfg:
                    for succ in dfg.successors(nid):
                        queue.append((succ, depth + 1))
            result[rng.id] = (classical, pqc)
        return result

    # ── SP3b: seed split domain separation ───────────────────────

    def _check_sp3b(self, cpg: FunctionCPG) -> list[Finding]:
        """
        Two strategies:
        1. CPG dataflow: from single RNG, check if path to BOTH components
           passes through a KDF/hash node.
        2. Text pattern: detect direct seed slicing (seed[:32]) without KDF.
        """
        project = _project_name(cpg.site.file_path)
        rng_nodes = cpg.get_nodes_by_label(CryptoLabel.RNG_CALL)

        # Only relevant when there's a single explicit RNG source
        # AND no implicit RNG that provides independence
        implicit_rng = [n for n in cpg.nodes.values()
                        if n.id != -1 and n.label != CryptoLabel.RNG_CALL
                        and _IMPLICIT_RNG.search(n.text)]
        implicit_c = any(any(kw in n.text for kw in ("x25519", "X25519", "ecdh", "ecc", "sntrup"))
                         for n in implicit_rng)
        implicit_p = any(any(kw in n.text for kw in ("mlkem", "MLKEM", "kyber", "Kyber", "kem_enc"))
                         for n in implicit_rng)
        if implicit_c and implicit_p:
            return []  # Both components have independent internal RNG
        if len(rng_nodes) != 1:
            return []

        findings = []
        rng = rng_nodes[0]

        # Strategy 1: CPG dataflow — does a KDF sit on every path from
        # RNG to each component type?
        (path_c, path_p, kdf_c, kdf_p) = \
            self._kdf_between_rng_and_components(cpg, rng.id)

        if path_c and path_p:
            # RNG feeds both component types
            if kdf_c and kdf_p:
                # Every path to every component passes through a KDF
                findings.append(self._finding(
                    cpg, project, "SP3b", Verdict.PASS, Severity.LOW,
                    f"Single RNG at L{rng.line} is domain-separated via "
                    f"KDF/hash on all dataflow paths to both components.",
                    [rng.line]))
            else:
                missing = []
                if not kdf_c:
                    missing.append("classical")
                if not kdf_p:
                    missing.append("PQC")
                findings.append(self._finding(
                    cpg, project, "SP3b", Verdict.FAIL, Severity.HIGH,
                    f"Single RNG at L{rng.line} feeds both components but "
                    f"at least one dataflow path to {', '.join(missing)} "
                    f"lacks KDF domain separation.",
                    [rng.line]))
        elif path_c or path_p:
            # Only one component type is reachable — can't fully confirm
            which = "classical" if path_c else "PQC"
            findings.append(self._finding(
                cpg, project, "SP3b", Verdict.UNCERTAIN, Severity.MEDIUM,
                f"Single RNG at L{rng.line} reaches {which} component "
                f"but no dataflow path to the other was found; "
                f"cannot confirm domain separation.",
                [rng.line]))

        # Strategy 2: text pattern — direct seed slicing
        findings.extend(self._check_seed_slicing(cpg, project))

        return findings

    def _kdf_between_rng_and_components(
        self, cpg: FunctionCPG, rng_id: int,
    ) -> tuple[bool, bool, bool, bool]:
        """Per-path KDF check using ``cpg.dataflow_path_has_label()``.

        Returns a 4-tuple of booleans:
            (path_to_classical, path_to_pqc,
             kdf_on_classical_path, kdf_on_pqc_path)

        *path_to_X* is True when at least one dataflow path exists from the
        RNG node to any node labelled X.  *kdf_on_X_path* is True only when
        **every** such path passes through a COMBINER (KDF) node — i.e. the
        corresponding ``dataflow_path_has_label`` call returns True.
        """
        classical_nodes = cpg.get_nodes_by_label(CryptoLabel.CLASSICAL_OP)
        pqc_nodes = cpg.get_nodes_by_label(CryptoLabel.PQC_OP)

        path_to_classical = False
        path_to_pqc = False
        kdf_on_classical_path = True   # vacuously true; flipped on first miss
        kdf_on_pqc_path = True

        # Build a lightweight reachability set once so we can skip components
        # that aren't downstream of this RNG at all.
        dfg = nx.DiGraph()
        for n in cpg.nodes.values():
            dfg.add_node(n.id)
        for e in cpg.edges:
            if e.edge_type == "dataflow":
                dfg.add_edge(e.src, e.dst)

        reachable: set[int] = set()
        queue: deque[int] = deque([rng_id])
        while queue:
            nid = queue.popleft()
            if nid in reachable:
                continue
            reachable.add(nid)
            if nid in dfg:
                for succ in dfg.successors(nid):
                    queue.append(succ)

        for comp in classical_nodes:
            if comp.id not in reachable:
                continue
            path_to_classical = True
            if not cpg.dataflow_path_has_label(
                rng_id, comp.id, CryptoLabel.COMBINER
            ):
                kdf_on_classical_path = False

        for comp in pqc_nodes:
            if comp.id not in reachable:
                continue
            path_to_pqc = True
            if not cpg.dataflow_path_has_label(
                rng_id, comp.id, CryptoLabel.COMBINER
            ):
                kdf_on_pqc_path = False

        # If no path existed for a component type, reset its KDF flag to False
        if not path_to_classical:
            kdf_on_classical_path = False
        if not path_to_pqc:
            kdf_on_pqc_path = False

        return (path_to_classical, path_to_pqc,
                kdf_on_classical_path, kdf_on_pqc_path)

    @staticmethod
    def _is_kdf(node: CPGNode) -> bool:
        if node.label == CryptoLabel.COMBINER and "kdf" in (node.detail or "").lower():
            return True
        for kdf_name in COMBINER_KDF:
            if kdf_name in node.text:
                return True
        return False

    def _check_seed_slicing(self, cpg: FunctionCPG,
                             project: str) -> list[Finding]:
        """Text-pattern fallback: detect direct seed[:32]/seed[32:] without KDF."""
        body = cpg.site.body_text
        findings = []

        for pattern in _SEED_SLICE_RES:
            for match in pattern.finditer(body):
                seed_var = match.group(1)
                # Check if a KDF appears between seed origin and this slice
                preceding = body[:match.start()]
                seed_first = preceding.find(seed_var)
                if seed_first == -1:
                    continue
                between = body[seed_first:match.start()]
                has_kdf = any(kdf in between for kdf in COMBINER_KDF)
                if not has_kdf:
                    line = body[:match.start()].count("\n") + cpg.site.start_line
                    findings.append(self._finding(
                        cpg, project, "SP3b", Verdict.FAIL, Severity.HIGH,
                        f"Direct seed slicing of '{seed_var}' without KDF "
                        f"domain separation: `{match.group(0).strip()}`",
                        [line]))

        return findings

    # ── Finding factory ──────────────────────────────────────────

    @staticmethod
    def _finding(cpg: FunctionCPG, project: str, sub: str,
                  verdict: Verdict, severity: Severity,
                  evidence: str, lines: list[int] = None) -> Finding:
        return Finding(
            project=project,
            file_path=cpg.site.file_path,
            function_name=cpg.site.function_name,
            sp="SP3", sub_property=sub,
            verdict=verdict, severity=severity,
            evidence=evidence, lines=lines or [],
        )
