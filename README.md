# HKEMLint

A static analysis tool for detecting security property violations in hybrid Key Encapsulation Mechanism (KEM) implementations. HKEMLint constructs inter-procedural Code Property Graphs (CPGs) and performs graph-based vulnerability detection across C, C++, Go, Rust, and Java codebases.

## DataSet for Paper
Due to the large size of the dataset (2 GiB), we have uploaded it to IPFS (InterPlanetary File System) to allow reliable and decentralized access. The dataset can be downloaded using the following IPFS link:
https://bafybeidstd6k4pxqrtp2f756nuvfamllhdygpdew3nt63py5hvxpstv54u.ipfs.dweb.link?filename=DataSet.zip


## Installation

```bash
pip install -e .
```

To use the Neo4j backend (Cypher-based graph queries):

```bash
pip install -e ".[neo4j]"
```

### Requirements

- Python >= 3.9
- Dependencies installed automatically: `tree-sitter`, `networkx`, `click`, and language grammars for C/C++/Rust/Go/Java.
- **Neo4j backend (optional)**: Neo4j >= 5.0 running locally or remotely.

## Usage

### Scan a project

```bash
hkemlint scan <project_path>
```

Example:

```bash
hkemlint scan ./DataSet/wolfssl
```

### Options

| Flag | Description |
|------|-------------|
| `--rule S1,S4` | Only run specific rule categories (comma-separated) |
| `--format json` | Output results as JSON (default: `text`) |
| `--backend neo4j` | Use Neo4j/Cypher backend instead of in-memory NetworkX |
| `--neo4j-uri` | Neo4j bolt URI (default: `bolt://localhost:7687`) |
| `--include-tests` | Include test files in the scan |
| `-v` / `--verbose` | Show hybrid site details and UNCERTAIN findings |

### Examples

```bash
# Scan with JSON output
hkemlint scan ./project --format json

# Only check combiner and zeroization rules
hkemlint scan ./project --rule S2,S4,S5

# Use Neo4j backend with Cypher pattern-matching
hkemlint scan ./project --backend neo4j

# Show all detected hybrid sites
hkemlint locate ./project
```

### Run as a Python module

```bash
python -m hkemlint scan <project_path>
```

## Vulnerability Taxonomy

HKEMLint detects 10 vulnerability types across 6 categories:

| Rule | Description |
|------|-------------|
| **S1-1** | Parameter Mismatch — hybrid group ID maps to wrong component parameters |
| **S2-1** | Weak Combiner — shared secrets combined with XOR or raw concatenation |
| **S2-2** | Missing Context Binding — combiner does not bind ciphertext, public key, or algorithm ID |
| **S3-1** | Key Domain Violation — same classical key used in both hybrid and standalone contexts |
| **S3-2** | Shared Seed Without KDF — single RNG seed feeds both components without domain separation |
| **S4-1** | Undestroyed Intermediate on Half-Success (Encaps) — component shared secret not zeroized on peer failure |
| **S4-2** | Undestroyed Intermediate on Completion (Encaps) — intermediate keys persist after combining |
| **S5-1** | Undestroyed Intermediate on Half-Success (Decaps) — same as S4-1 for decapsulation |
| **S5-2** | Undestroyed Intermediate on Completion (Decaps) — same as S4-2 for decapsulation |
| **S6-1** | Silent Single-KEM Fallback — PQC failure silently degrades to classical-only key |

## How It Works

HKEMLint operates in three phases:

1. **Site Location** — Tree-sitter parses source files; keyword matching identifies functions containing hybrid KEM code.
2. **CPG Construction & Labeling** — We leverage the [Fraunhofer AISEC CPG library](https://github.com/Fraunhofer-AISEC/cpg) to construct inter-procedural Code Property Graphs for C/C++, Go, TypeScript, and Python via native frontends, and for Rust via its LLVM IR frontend. The resulting graph (with `:EOG`, `:DFG`, `:AST` edges) is pushed into Neo4j, then projected into our analysis schema. A two-pass Cypher labeler assigns operation labels (`PARAM`, `KEYGEN`, `ENCAP`, `DECAP`, `COMBINER`) and value labels (`ek_1`, `ek_2`, `dk_1`, `dk_2`, `c_1`, `c_2`, `K_1`, `K_2`, `K`) to CPG nodes via `SET` statements.
3. **Graph-Based Checking** — Each S-rule is expressed as a Cypher `MATCH` pattern over the labeled CPG in Neo4j (variable-length path traversal, existential sub-queries, label filtering on `:CFG` and `:DATAFLOW` edges).

### Fraunhofer CPG Setup

The Neo4j backend requires the [Fraunhofer AISEC CPG](https://github.com/Fraunhofer-AISEC/cpg) tool:

```bash
# 1. Clone and build cpg-neo4j
git clone https://github.com/Fraunhofer-AISEC/cpg.git
cd cpg/cpg-neo4j
../gradlew installDist

# 2. Start Neo4j with APOC plugin
docker run -p 7474:7474 -p 7687:7687 -d \
  -e NEO4J_AUTH=neo4j/password \
  -e NEO4JLABS_PLUGINS='["apoc"]' neo4j:5

# 3. Set the binary path
export CPG_NEO4J_BIN=/path/to/cpg/cpg-neo4j/build/install/cpg-neo4j/bin/cpg-neo4j
```

Requirements: Java >= 21, Neo4j >= 5 with APOC plugin.

If the Fraunhofer CPG binary is not available, HKEMLint automatically falls back to its built-in tree-sitter CPG builder.

### Neo4j Graph Schema

The Fraunhofer CPG populates Neo4j with its native schema (`:Node` hierarchy, `:EOG`/`:DFG`/`:AST` edges). A schema adapter then projects these into the analysis schema:

```
(:CPGNode {node_id, kind, text, line, op_label, val_label, component, detail, file_path, function_name})

Relationships:  -[:CFG]->  -[:DATAFLOW]->  -[:AST_CHILD]->
```

## License

This project is provided as a research artifact.
