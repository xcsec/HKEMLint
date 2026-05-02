from __future__ import annotations
import json
import os
import sys
import time
from typing import Optional

import click

from hkemlint.cpg.models import HybridSite, FunctionCPG, Finding, Verdict, Severity
from hkemlint.locator.site_finder import find_hybrid_sites, walk_source_files
from hkemlint.locator.call_graph import build_project_function_index, extract_callees
from hkemlint.cpg.cpg_builder import build_cpg
from hkemlint.cpg.labeler import label_nodes

from hkemlint.checkers.s1_param_mismatch import S1ParamMismatchChecker
from hkemlint.checkers.s2_combiner import S2CombinerChecker
from hkemlint.checkers.s3_domain import S3DomainChecker
from hkemlint.checkers.s4_encap_zeroize import S4EncapZeroizeChecker
from hkemlint.checkers.s5_decap_zeroize import S5DecapZeroizeChecker
from hkemlint.checkers.s6_fallback import S6FallbackChecker


ALL_CHECKERS = {
    "S1": S1ParamMismatchChecker,
    "S2": S2CombinerChecker,
    "S3": S3DomainChecker,
    "S4": S4EncapZeroizeChecker,
    "S5": S5DecapZeroizeChecker,
    "S6": S6FallbackChecker,
}


def _build_and_label_cpg(site: HybridSite,
                         func_index: Optional[dict] = None) -> Optional[FunctionCPG]:
    if site.ts_node is None:
        return None
    try:
        cpg = build_cpg(site)
        if cpg is None:
            return None

        if func_index is not None:
            from hkemlint.locator.parser import FunctionNode
            primary_as_fn = FunctionNode(
                name=site.function_name,
                start_line=site.start_line,
                end_line=site.end_line,
                body_text=site.body_text,
                language=site.language,
                file_path=site.file_path,
                ts_node=site.ts_node,
            )
            callees = extract_callees(primary_as_fn, func_index)
            for callee in callees:
                try:
                    callee_site = HybridSite(
                        file_path=callee.file_path,
                        language=callee.language,
                        function_name=callee.name,
                        start_line=callee.start_line,
                        end_line=callee.end_line,
                        body_text=callee.body_text,
                        match_strategy="callee",
                        ts_node=callee.ts_node,
                    )
                    callee_cpg = build_cpg(callee_site)
                    if callee_cpg:
                        label_nodes(callee_cpg)
                        offset = max(cpg.nodes.keys()) + 100 if cpg.nodes else 100
                        for nid, node in callee_cpg.nodes.items():
                            if nid == -1:
                                continue
                            node.id = nid + offset
                            cpg.nodes[node.id] = node
                        for edge in callee_cpg.edges:
                            if edge.src == -1 or edge.dst == -1:
                                continue
                            cpg.edges.append(type(edge)(
                                src=edge.src + offset,
                                dst=edge.dst + offset,
                                edge_type=edge.edge_type,
                            ))
                except Exception:
                    pass

        label_nodes(cpg)
        return cpg
    except Exception as e:
        click.echo(f"  WARNING: CPG build failed for {site.site_id}: {e}", err=True)
        return None


def _run_checkers(cpg: FunctionCPG, rule_filter: Optional[set[str]]) -> list[Finding]:
    findings = []
    for key, checker_cls in ALL_CHECKERS.items():
        if rule_filter and key not in rule_filter:
            continue
        try:
            checker = checker_cls()
            results = checker.check(cpg)
            findings.extend(results)
        except Exception as e:
            click.echo(
                f"  WARNING: {key} checker failed on "
                f"{cpg.site.site_id}: {e}", err=True
            )
    return findings


def _scan_neo4j(
    sites: list,
    func_index: dict | None,
    rule_filter: set[str] | None,
    uri: str, user: str, password: str,
    fmt: str, verbose: bool,
    project_path: str = "",
) -> list[Finding]:
    from hkemlint.neo4j_backend.driver import Neo4jConnection
    from hkemlint.neo4j_backend.exporter import export_cpg
    from hkemlint.neo4j_backend.labeler_cypher import label_nodes_cypher
    from hkemlint.neo4j_backend.checkers_cypher import run_all_checks

    conn = Neo4jConnection(uri=uri, user=user, password=password)
    try:
        conn.connect()
        conn.ensure_indexes()

        fraunhofer_ok = False
        if project_path:
            fraunhofer_ok = _try_fraunhofer_cpg(conn, project_path, fmt)

        if fraunhofer_ok:
            from hkemlint.neo4j_backend.schema_adapter import project_schema
            if fmt == "text":
                click.echo("  Fraunhofer CPG → Neo4j: projecting schema …")
            project_schema(conn)
            label_nodes_cypher(conn)
            all_findings = run_all_checks(conn)
            if rule_filter:
                all_findings = [
                    f for f in all_findings
                    if any(f.rule_id.startswith(r) for r in rule_filter)
                ]
            return all_findings

        if fmt == "text":
            click.echo("  Fraunhofer CPG not available; "
                        "using tree-sitter CPG exporter.")
        all_findings: list[Finding] = []
        for site in sites:
            cpg = _build_and_label_cpg(site, func_index)
            if cpg is None:
                continue

            conn.clear()
            export_cpg(conn, cpg)
            label_nodes_cypher(conn)
            findings = run_all_checks(conn)

            if rule_filter:
                findings = [
                    f for f in findings
                    if any(f.rule_id.startswith(r) for r in rule_filter)
                ]
            all_findings.extend(findings)

        return all_findings
    finally:
        conn.close()


def _try_fraunhofer_cpg(
    conn: "Neo4jConnection",
    project_path: str,
    fmt: str,
) -> bool:
    try:
        from hkemlint.neo4j_backend.cpg_fraunhofer import build_cpg_for_directory
        if fmt == "text":
            click.echo("  Running Fraunhofer CPG on project …")
        build_cpg_for_directory(project_path, conn)
        return True
    except RuntimeError as exc:
        if fmt == "text":
            click.echo(f"  WARNING: {exc}", err=True)
        return False
    except Exception as exc:
        if fmt == "text":
            click.echo(f"  WARNING: Fraunhofer CPG failed: {exc}", err=True)
        return False


def _format_finding(f: Finding) -> str:
    icon = {"FAIL": "X", "PASS": ".", "UNCERTAIN": "?"}.get(f.verdict, "?")
    color = {"FAIL": "red", "PASS": "green", "UNCERTAIN": "yellow"}.get(f.verdict, "white")
    lines_str = ",".join(str(l) for l in f.lines[:3])
    return click.style(
        f"  [{icon}] {f.rule_id:6s} {f.verdict:11s} "
        f"{f.file_path}:{lines_str}  {f.evidence[:80]}",
        fg=color,
    )


@click.group()
def main():
    pass


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--rule", default=None,
              help="Comma-separated rule filter (e.g., S1,S2,S4)")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--include-tests", is_flag=True, default=False)
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--backend", type=click.Choice(["networkx", "neo4j"]),
              default="networkx",
              help="Graph backend: networkx (in-memory) or neo4j (Cypher)")
@click.option("--neo4j-uri", default="bolt://localhost:7687",
              help="Neo4j bolt URI (only with --backend neo4j)")
@click.option("--neo4j-user", default="neo4j")
@click.option("--neo4j-password", default="neo4j")
def scan(project_path: str, rule: Optional[str], fmt: str,
         include_tests: bool, verbose: bool,
         backend: str, neo4j_uri: str, neo4j_user: str,
         neo4j_password: str):
    project_path = os.path.abspath(project_path)
    project_name = os.path.basename(project_path)

    rule_filter = set(s.strip().upper() for s in rule.split(",")) if rule else None

    t0 = time.time()
    sites = find_hybrid_sites(project_path, include_tests)
    locate_time = time.time() - t0

    if fmt == "text":
        click.echo(f"\n{'='*60}")
        click.echo(f"HKEMLint scan: {project_name}")
        click.echo(f"{'='*60}")
        click.echo(f"Phase 1: Found {len(sites)} hybrid sites ({locate_time:.1f}s)")
        if verbose:
            for s in sites:
                short = s.file_path.replace(project_path + "/", "")
                click.echo(f"  [{s.match_strategy:10s}] {short}:{s.start_line} :: {s.function_name}")

    source_files = walk_source_files(project_path, include_tests)
    func_index = build_project_function_index(project_path, source_files)
    if fmt == "text" and verbose:
        click.echo(f"Function index: {len(func_index)} functions")

    all_findings: list[Finding] = []
    t1 = time.time()

    if backend == "neo4j":
        all_findings = _scan_neo4j(
            sites, func_index, rule_filter,
            neo4j_uri, neo4j_user, neo4j_password,
            fmt, verbose,
            project_path=project_path,
        )
    else:
        for site in sites:
            cpg = _build_and_label_cpg(site, func_index)
            if cpg is None:
                continue
            findings = _run_checkers(cpg, rule_filter)
            all_findings.extend(findings)

    check_time = time.time() - t1

    if fmt == "json":
        output = {
            "project": project_name,
            "project_path": project_path,
            "sites_found": len(sites),
            "scan_time_seconds": round(locate_time + check_time, 2),
            "findings": [
                {
                    "file": f.file_path.replace(project_path + "/", ""),
                    "function": f.function_name,
                    "rule_id": f.rule_id,
                    "verdict": f.verdict,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "lines": f.lines,
                }
                for f in all_findings
            ],
        }
        click.echo(json.dumps(output, indent=2))
    else:
        fails = [f for f in all_findings if f.verdict == "FAIL"]
        uncertain = [f for f in all_findings if f.verdict == "UNCERTAIN"]
        passes = [f for f in all_findings if f.verdict == "PASS"]

        click.echo(f"Phase 2+3: Analyzed {len(sites)} sites, "
                    f"produced {len(all_findings)} findings ({check_time:.1f}s)")
        click.echo(f"\nResults: {len(fails)} FAIL, "
                    f"{len(uncertain)} UNCERTAIN, {len(passes)} PASS")

        if fails:
            click.echo(f"\n--- FAILURES ---")
            for f in fails:
                click.echo(_format_finding(f))

        if uncertain and verbose:
            click.echo(f"\n--- UNCERTAIN ---")
            for f in uncertain:
                click.echo(_format_finding(f))

        click.echo(f"\nTotal time: {locate_time + check_time:.1f}s")


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--include-tests", is_flag=True, default=False)
def locate(project_path: str, include_tests: bool):
    project_path = os.path.abspath(project_path)
    sites = find_hybrid_sites(project_path, include_tests)

    click.echo(f"Found {len(sites)} hybrid sites in {os.path.basename(project_path)}")
    for s in sites:
        short = s.file_path.replace(project_path + "/", "")
        kws = ", ".join(s.matched_keywords[:4])
        click.echo(f"  [{s.match_strategy:10s}] {short}:{s.start_line} :: "
                    f"{s.function_name}  [{kws}]")


if __name__ == "__main__":
    main()
