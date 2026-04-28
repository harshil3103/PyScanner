from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Literal

from pyscanner.config.settings import ScanConfig
from pyscanner.core.remediation import get_remediation
from pyscanner.core.scoring import compute_score, score_label, severity_label
from pyscanner.ingestion.ast_parse import parse_python_file
from pyscanner.ingestion.discovery import discover_python_files
from pyscanner.ingestion.manifests import extract_manifests
from pyscanner.ingestion.reader import read_file_unit
from pyscanner.learning.shadow_generator import propose_shadow_rule
from pyscanner.llm.runner import LlmRunner
from pyscanner.models.findings import Reference, ScanReport, ScanSummary, SecurityFinding
from pyscanner.models.raw import RawFinding
from pyscanner.persistence.sqlite_store import SqliteStore
from pyscanner.sast.engine import run_sast
from pyscanner.sast.rules.supply_chain import check_manifests
from pyscanner.security.secrets_manager import SecretStore
from pyscanner.slicer.slice_builder import build_slice_for_finding
from pyscanner.telemetry.otel import trace_span
from pyscanner.triage.router import route_finding
from pyscanner.triage.slm_client import SlmClient

_RULE_SEVERITY: dict[str, float] = {
    # Injection / code execution
    "py.injection.eval-exec": 9.5,
    "py.subprocess.shell-true": 8.5,
    "py.os.system": 8.2,
    # Deserialization
    "py.pickle.loads": 8.8,
    "py.yaml.unsafe-load": 7.5,
    # Secrets
    "py.secrets.aws-cred": 9.0,
    "py.secrets.generic-assignment": 7.0,
    "py.secrets.private-key": 9.5,
    "py.secrets.long-string": 5.0,
    # SSL / TLS
    "py.ssl.verify-false": 7.2,
    # Cryptography
    "py.crypto.weak-hash": 5.5,
    "py.crypto.random-not-secrets": 6.0,
    # SQL Injection
    "py.sql.injection": 9.0,
    # Path Traversal
    "py.path.traversal": 7.5,
    "py.path.open-variable": 6.5,
    # XSS
    "py.xss.markup": 7.0,
    "py.xss.render-template-string": 8.5,
    "py.xss.mark-safe": 7.0,
    "py.xss.response-html": 6.5,
    # File Upload
    "py.upload.unrestricted": 7.8,
    "py.upload.no-validation": 7.0,
    # Misconfiguration
    "py.config.debug-enabled": 7.5,
    "py.config.cors-wildcard": 6.5,
    "py.config.allowed-hosts-wildcard": 6.0,
    "py.config.weak-secret-key": 8.0,
    # Supply Chain
    "py.supply.typosquat": 8.5,
    "py.supply.known-malicious": 10.0,
}


def _raw_to_security(
    f: RawFinding,
    *,
    provenance: Literal["rule", "slm", "llm", "hybrid"] = "rule",
    confidence: float = 0.75,
) -> SecurityFinding:
    vtype = f.tags[0] if f.tags else f.rule_id
    sev = _RULE_SEVERITY.get(f.rule_id, 6.0)
    sev_lbl = severity_label(sev)
    
    refs: list[Reference] = []
    if f.cwe_id:
        refs.append(Reference(kind="cwe", id_or_url=f.cwe_id))

    # Enrich with remediation catalog
    owasp_cat = None
    remedy_hint = None
    remedy_code = None
    explanation = f.message

    rem = get_remediation(f.rule_id)
    if rem:
        owasp_cat = rem.owasp
        remedy_hint = rem.fix_hint
        remedy_code = rem.safe_code
        if rem.impact:
            explanation = f"{f.message}\nImpact: {rem.impact}"

    return SecurityFinding(
        file_path=f.file_path,
        line_number=f.start_line,
        end_line=f.end_line,
        vulnerability_type=vtype,
        cwe_id=f.cwe_id,
        severity_score=sev,
        severity_label=sev_lbl,  # type: ignore
        confidence_score=confidence,
        explanation=explanation,
        owasp_category=owasp_cat,
        remediation_code=remedy_code,
        remediation_suggestion=remedy_hint,
        references=refs,
        provenance=provenance,
        rule_id=f.rule_id,
        slice_id=None,
        evidence=f.evidence,
    )


def run_scan(
    target: Path,
    config: ScanConfig,
    *,
    store: SqliteStore | None = None,
    secret_store: SecretStore | None = None,
) -> ScanReport:
    t0 = time.perf_counter()
    scan_id = store.new_scan_id() if store else str(uuid.uuid4())
    manifest = extract_manifests(target)
    if target.is_file() and target.suffix == ".py":
        paths = [target.resolve()]
    elif target.is_dir():
        paths = discover_python_files(target)
    else:
        paths = []

    findings: list[SecurityFinding] = []
    raw_total = 0
    slm_calls = 0
    llm_runner = LlmRunner(config, secret_store=secret_store)
    slm = SlmClient(config)

    # --- Supply-chain checks on declared dependencies ---
    if manifest.declared_packages:
        manifest_source = manifest.requirements_files[0] if manifest.requirements_files else (
            manifest.pyproject_path or "<manifest>"
        )
        supply_findings = check_manifests(manifest.declared_packages, file_path=manifest_source)
        for sf_raw in supply_findings:
            raw_total += 1
            findings.append(_raw_to_security(sf_raw, confidence=0.90))

    with trace_span("scan", scan_id=scan_id):
        for path in paths:
            unit = read_file_unit(path)
            if not unit.content:
                continue
            parsed = parse_python_file(unit)
            raw_list = run_sast(parsed, rule_packs=config.rule_packs)
            raw_total += len(raw_list)
            for raw in raw_list:
                slice_ = build_slice_for_finding(
                    tree=parsed.stdlib_ast,
                    source=parsed.source,
                    finding=raw,
                    token_budget=config.slice_token_budget,
                )
                triage = route_finding(raw, slice_, config=config, slm=slm)
                if triage.used_slm:
                    slm_calls += 1
                if triage.label == "false_positive" and triage.confidence >= 0.85:
                    continue
                if triage.label == "uncertain" and config.enable_llm and not config.offline:
                    llm_f = llm_runner.analyze(raw, slice_)
                    if llm_f:
                        # Enrich LLM finding with local severity label & remediation
                        sev_lbl = severity_label(llm_f.severity_score)
                        upd = {"severity_label": sev_lbl, "slice_id": slice_.slice_id, "evidence": raw.evidence}
                        rem = get_remediation(llm_f.rule_id or "")
                        if rem:
                            upd["owasp_category"] = rem.owasp
                            if not llm_f.remediation_suggestion:
                                upd["remediation_suggestion"] = rem.fix_hint
                            if not llm_f.remediation_code:
                                upd["remediation_code"] = rem.safe_code
                        
                        llm_f = llm_f.model_copy(update=upd)
                        findings.append(llm_f)
                        # --- Learning: propose shadow rule from LLM-confirmed findings ---
                        _maybe_persist_shadow_rule(llm_f, store)
                        continue
                prov = "hybrid" if triage.label == "true_positive" and triage.used_slm else "rule"
                conf = max(triage.confidence, 0.55) if triage.used_slm else 0.72
                sf = _raw_to_security(raw, provenance=prov, confidence=conf)
                sf = sf.model_copy(update={"slice_id": slice_.slice_id})
                findings.append(sf)

    duration_ms = int((time.perf_counter() - t0) * 1000)
    score = compute_score(findings)
    
    report = ScanReport(
        scan_id=scan_id,
        duration_ms=duration_ms,
        config_summary={
            "offline": config.offline,
            "enable_slm": config.enable_slm,
            "enable_llm": config.enable_llm,
            "rule_packs": config.rule_packs,
            "manifest": manifest.model_dump(),
        },
        metrics=ScanSummary(
            files_scanned=len(paths),
            raw_findings=raw_total,
            llm_calls=llm_runner.calls,
            slm_calls=slm_calls,
            estimated_cost_usd=round(llm_runner.calls * 0.004, 4),
        ),
        findings=findings,
        security_score=score,
        score_label=score_label(score),
    )
    if store:
        store.save_scan(report)
    return report


def _maybe_persist_shadow_rule(finding: SecurityFinding, store: SqliteStore | None) -> None:
    """Attempt to generate and persist a shadow rule from an LLM-confirmed finding."""
    draft = propose_shadow_rule(finding)
    if draft is None:
        return
    if store is not None:
        try:
            from pyscanner.learning.rule_validator import validate_shadow_rule_text

            ok, _ = validate_shadow_rule_text(draft.yaml_text)
            if ok:
                with store._conn() as c:
                    c.execute(
                        "INSERT OR IGNORE INTO shadow_rules(rule_id, yaml, state) VALUES(?,?,?)",
                        (
                            finding.rule_id or finding.vulnerability_type,
                            draft.yaml_text,
                            "shadow",
                        ),
                    )
        except Exception:
            pass  # best-effort — don't break scans for learning failures

