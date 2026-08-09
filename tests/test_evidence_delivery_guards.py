from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from pypdf import PdfWriter
from typer.testing import CliRunner

from aiscience.cli import app
from aiscience.delivery import assess_delivery_readiness
from aiscience.demo import create_demo
from aiscience.gates import GateManager
from aiscience.local_cas import archive_output
from aiscience.models import (
    ArtifactStatus,
    ClaimRecord,
    ExperimentRecord,
    GenerationTrace,
    ObjectRef,
    ReproductionLevel,
    ReviewFinding,
    ReviewReportRecord,
    ReviewSeverity,
    SourceRecord,
    SupportStatus,
    generation_output_digest,
    new_id,
)
from aiscience.paper import validate_paper
from aiscience.scaffold import record_artifact
from aiscience.storage import LedgerStore


def _git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True
    )
    (path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "seed"], cwd=path, check=True, capture_output=True
    )


def _install_project_template(repo: Path) -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / ".agents"
        / "skills"
        / "research-orchestrator"
        / "assets"
        / "project-template"
    )
    target = repo / ".agents" / "skills" / "research-orchestrator" / "assets"
    target.mkdir(parents=True)
    import shutil

    shutil.copytree(source, target / "project-template")


def _fake_pdf_build(repo: Path, project_id: str) -> dict[str, object]:
    build = repo / "projects" / project_id / "paper" / "build"
    build.mkdir(parents=True, exist_ok=True)
    for language in ("en", "zh"):
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        with (build / f"manuscript-{language}.pdf").open("wb") as stream:
            writer.write(stream)
    return {"status": "built", "validation": {"ok": True}}


@pytest.fixture
def guarded_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    _git_repo(tmp_path)
    _install_project_template(tmp_path)
    monkeypatch.setattr("aiscience.demo.build_paper", _fake_pdf_build)
    result = create_demo(tmp_path)
    assert result["status"] == "created"
    project = tmp_path / "projects" / "demo-robust-location"
    assert validate_paper(tmp_path, "demo-robust-location")["ok"] is True
    return tmp_path, project


def test_truncated_pdf_blocks_paper_and_g2(guarded_demo: tuple[Path, Path]) -> None:
    repo, project = guarded_demo
    (project / "paper" / "build" / "manuscript-en.pdf").write_bytes(
        b"%PDF-1.4\n% truncated\n"
    )

    paper = validate_paper(repo, project.name)
    readiness = assess_delivery_readiness(repo, project.name)

    assert "PDF_STRUCTURE_INVALID" in {item["code"] for item in paper["findings"]}
    assert "PDF_STRUCTURE_INVALID" in {item["code"] for item in readiness["findings"]}


def test_package_id_cannot_escape_delivery_root(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    manifest_path = project / "delivery" / "candidate" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["package_id"] = "../../outside"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    assert "G2_PACKAGE_ID_INVALID" in {item["code"] for item in readiness["findings"]}


def test_pdf_validation_capability_is_fail_closed(
    guarded_demo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, project = guarded_demo
    original = __import__("aiscience.paper", fromlist=["shutil"]).shutil.which
    monkeypatch.setattr(
        "aiscience.paper.shutil.which",
        lambda name: (
            None if name.removesuffix(".exe") in {"pdfinfo", "pdftoppm"} else original(name)
        ),
    )

    result = validate_paper(repo, project.name)

    assert "PDF_VALIDATION_CAPABILITY_UNAVAILABLE" in {
        item["code"] for item in result["findings"]
    }


def test_orphan_ledger_object_blocks_g2(guarded_demo: tuple[Path, Path]) -> None:
    repo, project = guarded_demo
    orphan = project / "objects" / "orphan" / "unanchored.v1.json"
    orphan.parent.mkdir(parents=True)
    anchored = next(project.glob("objects/**/*.json"))
    orphan.write_bytes(anchored.read_bytes())

    readiness = assess_delivery_readiness(repo, project.name)

    assert "G2_LEDGER_INTEGRITY_FAILED" in {
        item["code"] for item in readiness["findings"]
    }


def test_rollback_requires_post_cutoff_revalidation(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    LedgerStore(project).commit_object(
        project_id=project.name,
        object_type="project.transition",
        payload={"target": "designing", "rollback": True},
        event_type="project.transitioned",
        event_payload={"target": "designing", "rollback": True},
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert "G2_ROLLBACK_REVALIDATION_REQUIRED" in {
        item["code"] for item in readiness["findings"]
    }


def _citation_map(project: Path) -> tuple[Path, dict[str, object]]:
    path = project / "paper" / "citation-map.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_citation_ids_must_match_current_typed_ledger(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    path, citation_map = _citation_map(project)
    claims = citation_map["claims"]
    assert isinstance(claims, list) and isinstance(claims[0], dict)
    claims[0]["run_ids"] = ["run_000000000000"]
    path.write_text(json.dumps(citation_map, ensure_ascii=False), encoding="utf-8")

    result = validate_paper(repo, project.name)

    assert result["ok"] is False
    assert "CLAIM_RUN_MISMATCH" in {item["code"] for item in result["findings"]}


@pytest.mark.parametrize("support", [SupportStatus.MIXED, SupportStatus.REFUTED])
def test_citation_map_accepts_all_canonical_evidence_statuses(
    guarded_demo: tuple[Path, Path], support: SupportStatus
) -> None:
    repo, project = guarded_demo
    baseline = validate_paper(repo, project.name)
    store = LedgerStore(project)
    claim_ref = ObjectRef.model_validate(baseline["ledger_refs"]["claims"][0])
    claim = ClaimRecord.model_validate(store.read_object(claim_ref).payload)
    updated = claim.model_copy(update={"support_status": support})
    store.commit_object(
        project_id=project.name,
        object_type="claim",
        object_id=claim.claim_id,
        payload=updated.model_dump(mode="json"),
        dependencies=(*updated.evidence_refs, *updated.run_refs),
        supersedes=claim_ref,
        event_type="claim.recorded",
    )
    path, citation_map = _citation_map(project)
    mapped_claim = next(
        item
        for item in citation_map["claims"]
        if isinstance(item, dict) and item.get("claim_id") == claim.claim_id
    )
    mapped_claim["support_status"] = support.value
    path.write_text(json.dumps(citation_map, ensure_ascii=False), encoding="utf-8")

    result = validate_paper(repo, project.name)

    assert result["ok"] is True, result["findings"]


def test_valid_bib_key_cannot_be_substituted_for_the_evidence_source(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    unrelated = SourceRecord(
        source_id="source_aaaaaaaaaaaa",
        project_id=project.name,
        title="Unrelated fixture",
        local_fixture=True,
        version_label="fixture-v1",
        access_level="metadata_only",
        license="CC0-1.0",
    )
    store.commit_object(
        project_id=project.name,
        object_type="source",
        object_id=unrelated.source_id,
        payload=unrelated.model_dump(mode="json"),
        event_type="literature.source_recorded",
    )
    bib = project / "paper" / "references.bib"
    bib.write_text(
        bib.read_text(encoding="utf-8")
        + "\n@misc{unrelated, title={Unrelated fixture}, author={Test}}\n",
        encoding="utf-8",
    )
    path, citation_map = _citation_map(project)
    sources = citation_map["sources"]
    assert isinstance(sources, list)
    sources.append({"bib_key": "unrelated", "source_id": unrelated.source_id})
    claims = citation_map["claims"]
    assert isinstance(claims, list) and isinstance(claims[1], dict)
    claims[1]["citations"] = ["unrelated"]
    path.write_text(json.dumps(citation_map, ensure_ascii=False), encoding="utf-8")

    result = validate_paper(repo, project.name)

    assert "CLAIM_CITATION_EVIDENCE_MISMATCH" in {
        item["code"] for item in result["findings"]
    }


def test_review_report_rejects_boolean_counts_and_demo_status_in_formal_project() -> None:
    reference = ObjectRef(
        object_id="protocol_123456789abc",
        object_type="research.protocol",
        version=1,
        path="objects/research.protocol/protocol_123456789abc.v1.json",
        sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="risk_counts"):
        ReviewReportRecord(
            review_id="review_123456789abc",
            project_id="study-01",
            status="passed_for_delivery",
            risk_counts={"high": False, "medium": 0, "low": 0},  # type: ignore[dict-item]
            covered_refs=(reference,),
            reproducibility="full",
        )
    with pytest.raises(ValueError, match="demo"):
        ReviewReportRecord(
            review_id="review_123456789abc",
            project_id="study-01",
            status="passed_for_demo_candidate",
            risk_counts={"high": 0, "medium": 0, "low": 0},
            covered_refs=(reference,),
            reproducibility="full",
        )


def test_tampered_run_log_blocks_paper_validation(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    baseline = validate_paper(repo, project.name)
    store = LedgerStore(project)
    log_path = project / "runs" / "trace.log"
    log_path.write_text("observed log\n", encoding="utf-8")
    log_ref = record_artifact(
        project,
        project.name,
        source=log_path,
        object_type="experiment.log",
    )
    old_run_ref = ObjectRef.model_validate(baseline["ledger_refs"]["runs"][0])
    old_run_object = store.read_object(old_run_ref)
    old_run = ExperimentRecord.model_validate(old_run_object.payload)
    updated_run = old_run.model_copy(update={"log_refs": (log_ref,)})
    updated_run_ref = store.commit_object(
        project_id=project.name,
        object_type="experiment",
        object_id=old_run.run_id,
        payload=updated_run.model_dump(mode="json"),
        dependencies=(*old_run_object.dependencies, log_ref),
        supersedes=old_run_ref,
        event_type="experiment.recorded",
    )
    for raw_claim_ref in baseline["ledger_refs"]["claims"]:
        old_claim_ref = ObjectRef.model_validate(raw_claim_ref)
        old_claim = ClaimRecord.model_validate(store.read_object(old_claim_ref).payload)
        updated_claim = old_claim.model_copy(
            update={
                "run_refs": tuple(
                    updated_run_ref if reference == old_run_ref else reference
                    for reference in old_claim.run_refs
                )
            }
        )
        store.commit_object(
            project_id=project.name,
            object_type="claim",
            object_id=old_claim.claim_id,
            payload=updated_claim.model_dump(mode="json"),
            dependencies=(*updated_claim.evidence_refs, *updated_claim.run_refs),
            supersedes=old_claim_ref,
            event_type="claim.recorded",
        )
    log_path.write_text("tampered log\n", encoding="utf-8")

    result = validate_paper(repo, project.name)

    assert "RUN_TRACE_SOURCE_STALE" in {item["code"] for item in result["findings"]}


@pytest.mark.parametrize("mutation", ["missing", "tampered"])
def test_invalid_local_cas_blob_blocks_paper_and_g2(
    guarded_demo: tuple[Path, Path], mutation: str,
) -> None:
    repo, project = guarded_demo
    baseline = validate_paper(repo, project.name)
    store = LedgerStore(project)
    run_root = project / "runs" / "cas-trace"
    run_root.mkdir(parents=True)
    source = project / "results" / "restricted.bin"
    source.write_bytes(b"restricted fixture")
    archived = archive_output(
        project_root=project,
        run_root=run_root,
        output_path=source,
        relative_path="results/restricted.bin",
        declared_sensitive=False,
        redistributable=False,
    )
    manifest = run_root / str(archived["cas_manifest_path"])
    manifest_relative = manifest.relative_to(project).as_posix()
    artifact_ref = store.commit_object(
        project_id=project.name,
        object_type="experiment.artifact",
        payload={
            "source_path": manifest_relative,
            "source_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "metadata": archived,
        },
        event_type="experiment.artifact.recorded",
    )
    old_run_ref = ObjectRef.model_validate(baseline["ledger_refs"]["runs"][0])
    old_run_object = store.read_object(old_run_ref)
    old_run = ExperimentRecord.model_validate(old_run_object.payload)
    updated_run = old_run.model_copy(
        update={
            "artifact_refs": (*old_run.artifact_refs, artifact_ref),
            "reproduction_level": ReproductionLevel.LOCAL_ONLY,
        }
    )
    updated_run_ref = store.commit_object(
        project_id=project.name,
        object_type="experiment",
        object_id=old_run.run_id,
        payload=updated_run.model_dump(mode="json"),
        dependencies=(*old_run_object.dependencies, artifact_ref),
        supersedes=old_run_ref,
        event_type="experiment.recorded",
    )
    for raw_claim_ref in baseline["ledger_refs"]["claims"]:
        old_claim_ref = ObjectRef.model_validate(raw_claim_ref)
        old_claim = ClaimRecord.model_validate(store.read_object(old_claim_ref).payload)
        updated_claim = old_claim.model_copy(
            update={
                "run_refs": tuple(
                    updated_run_ref if reference == old_run_ref else reference
                    for reference in old_claim.run_refs
                )
            }
        )
        store.commit_object(
            project_id=project.name,
            object_type="claim",
            object_id=old_claim.claim_id,
            payload=updated_claim.model_dump(mode="json"),
            dependencies=(*updated_claim.evidence_refs, *updated_claim.run_refs),
            supersedes=old_claim_ref,
            event_type="claim.recorded",
        )
    algorithm, digest = str(archived["cas_address"]).split(":", 1)
    blob = project / ".aiscience-data" / "cas" / algorithm / digest[:2] / digest
    if mutation == "missing":
        blob.unlink()
    else:
        blob.write_bytes(b"x" * blob.stat().st_size)

    paper = validate_paper(repo, project.name)
    readiness = assess_delivery_readiness(repo, project.name)

    assert "RUN_LOCAL_CAS_INVALID" in {item["code"] for item in paper["findings"]}
    assert "RUN_LOCAL_CAS_INVALID" in {item["code"] for item in readiness["findings"]}


def test_retracted_source_blocks_claim_validation(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    baseline = validate_paper(repo, project.name)
    refs = baseline["ledger_refs"]
    store = LedgerStore(project)
    source_ref = ObjectRef.model_validate(refs["sources"][0])
    old_source = SourceRecord.model_validate(store.read_object(source_ref).payload)
    source_v2 = old_source.model_copy(update={"retracted": True})
    source_ref_v2 = store.commit_object(
        project_id=project.name,
        object_type="source",
        object_id=old_source.source_id,
        payload=source_v2.model_dump(mode="json"),
        supersedes=source_ref,
        event_type="source.recorded",
    )
    evidence_ref = ObjectRef.model_validate(refs["evidence"][0])
    evidence_object = store.read_object(evidence_ref)
    evidence_payload = dict(evidence_object.payload)
    evidence_payload["source_ref"] = source_ref_v2.model_dump(mode="json")
    evidence_ref_v2 = store.commit_object(
        project_id=project.name,
        object_type="evidence.card",
        object_id=evidence_ref.object_id,
        payload=evidence_payload,
        dependencies=(source_ref_v2,),
        supersedes=evidence_ref,
        event_type="evidence.card_recorded",
    )
    claim_ref = next(
        ObjectRef.model_validate(raw)
        for raw in refs["claims"]
        if evidence_ref.object_id
        in {
            ref["object_id"]
            for ref in store.read_object(ObjectRef.model_validate(raw)).payload["evidence_refs"]
        }
    )
    claim = ClaimRecord.model_validate(store.read_object(claim_ref).payload)
    claim_v2 = claim.model_copy(update={"evidence_refs": (evidence_ref_v2,)})
    store.commit_object(
        project_id=project.name,
        object_type="claim",
        object_id=claim.claim_id,
        payload=claim_v2.model_dump(mode="json"),
        dependencies=(*claim_v2.evidence_refs, *claim_v2.run_refs),
        supersedes=claim_ref,
        event_type="claim.recorded",
    )

    result = validate_paper(repo, project.name)

    assert result["ok"] is False
    assert "SOURCE_RETRACTED" in {item["code"] for item in result["findings"]}


def test_supported_orphan_claim_is_rejected(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    baseline = validate_paper(repo, project.name)
    store = LedgerStore(project)
    claim_ref = ObjectRef.model_validate(baseline["ledger_refs"]["claims"][0])
    claim = ClaimRecord.model_validate(store.read_object(claim_ref).payload)
    claim_v2 = claim.model_copy(update={"evidence_refs": (), "run_refs": ()})
    store.commit_object(
        project_id=project.name,
        object_type="claim",
        object_id=claim.claim_id,
        payload=claim_v2.model_dump(mode="json"),
        supersedes=claim_ref,
        event_type="claim.recorded",
    )
    path, citation_map = _citation_map(project)
    claims = citation_map["claims"]
    assert isinstance(claims, list) and isinstance(claims[0], dict)
    claims[0]["evidence_ids"] = []
    claims[0]["run_ids"] = []
    path.write_text(json.dumps(citation_map, ensure_ascii=False), encoding="utf-8")

    result = validate_paper(repo, project.name)

    assert result["ok"] is False
    assert "CLAIM_ORPHAN" in {item["code"] for item in result["findings"]}


def test_open_high_or_medium_review_blocks_g2_bundle(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    paper = validate_paper(repo, project.name)
    affected = tuple(ObjectRef.model_validate(raw) for raw in paper["ledger_refs"]["claims"])
    finding = ReviewFinding(
        finding_id=new_id("finding"),
        project_id=project.name,
        severity=ReviewSeverity.HIGH,
        category="evidence",
        description_zh="植入的错误引用尚未解决。",
        affected_refs=affected,
        disposition="open",
    )
    store.commit_object(
        project_id=project.name,
        object_type="review.finding",
        object_id=finding.finding_id,
        payload=finding.model_dump(mode="json"),
        dependencies=affected,
        event_type="review.finding_recorded",
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    codes = {item["code"] for item in readiness["findings"]}
    assert {"G2_REVIEW_FINDING_OPEN", "G2_REVIEW_NOT_CLEAN"} <= codes


@pytest.mark.parametrize(
    ("category", "severity"),
    [
        ("data_leakage", ReviewSeverity.HIGH),
        ("p_hacking", ReviewSeverity.HIGH),
        ("multiplicity_omission", ReviewSeverity.MEDIUM),
        ("figure_text_conflict", ReviewSeverity.MEDIUM),
        ("overgeneralization", ReviewSeverity.MEDIUM),
    ],
)
def test_audit_golden_findings_block_delivery(
    guarded_demo: tuple[Path, Path], category: str, severity: ReviewSeverity
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    paper = validate_paper(repo, project.name)
    affected = tuple(ObjectRef.model_validate(raw) for raw in paper["ledger_refs"]["claims"])
    finding = ReviewFinding(
        finding_id=new_id("finding"),
        project_id=project.name,
        severity=severity,
        category=category,
        description_zh=f"金样例植入未处置问题：{category}",
        affected_refs=affected,
        disposition="open",
    )
    store.commit_object(
        project_id=project.name,
        object_type="review.finding",
        object_id=finding.finding_id,
        payload=finding.model_dump(mode="json"),
        dependencies=affected,
        event_type="review.finding_recorded",
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    codes = {item["code"] for item in readiness["findings"]}
    assert {"G2_REVIEW_FINDING_OPEN", "G2_REVIEW_NOT_CLEAN"} <= codes


def test_clean_typed_bundle_has_explicit_delivery_governance(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is True
    manifest = json.loads(
        (project / "delivery" / "candidate" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["governance"]["authors"]
    assert manifest["governance"]["ai_disclosure"]["en"]
    assert manifest["governance"]["ai_disclosure"]["zh"]
    assert manifest["governance"]["license_statement"]
    assert all(record["license"] for record in manifest["files"])
    citation_map = json.loads(
        (project / "paper" / "citation-map.json").read_text(encoding="utf-8")
    )
    assert (
        hashlib.sha256((project / "paper" / "en" / "manuscript.md").read_bytes()).hexdigest()
        == citation_map["english_manuscript_sha256"]
    )


def test_manifest_cannot_overstate_the_weakest_cited_run(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    baseline = validate_paper(repo, project.name)
    store = LedgerStore(project)
    old_run_ref = ObjectRef.model_validate(baseline["ledger_refs"]["runs"][0])
    old_run_object = store.read_object(old_run_ref)
    old_run = ExperimentRecord.model_validate(old_run_object.payload)
    local_run = old_run.model_copy(
        update={"reproduction_level": ReproductionLevel.LOCAL_ONLY}
    )
    local_run_ref = store.commit_object(
        project_id=project.name,
        object_type="experiment",
        object_id=old_run.run_id,
        payload=local_run.model_dump(mode="json"),
        dependencies=old_run_object.dependencies,
        supersedes=old_run_ref,
        event_type="experiment.recorded",
    )
    new_claim_refs: list[ObjectRef] = []
    for raw_claim_ref in baseline["ledger_refs"]["claims"]:
        old_claim_ref = ObjectRef.model_validate(raw_claim_ref)
        old_claim = ClaimRecord.model_validate(store.read_object(old_claim_ref).payload)
        updated_refs = tuple(
            local_run_ref if reference == old_run_ref else reference
            for reference in old_claim.run_refs
        )
        new_claim = old_claim.model_copy(update={"run_refs": updated_refs})
        new_claim_refs.append(
            store.commit_object(
                project_id=project.name,
                object_type="claim",
                object_id=old_claim.claim_id,
                payload=new_claim.model_dump(mode="json"),
                dependencies=(*new_claim.evidence_refs, *new_claim.run_refs),
                supersedes=old_claim_ref,
                event_type="claim.recorded",
            )
        )
    finding_ref = next(
        event.object_ref
        for event in reversed(store.events())
        if event.object_ref is not None
        and event.object_ref.object_type == "review.finding"
        and store.is_current_reference(event.object_ref)
    )
    old_review_ref = next(
        event.object_ref
        for event in reversed(store.events())
        if event.object_ref is not None
        and event.object_ref.object_type == "review.report"
        and store.is_current_reference(event.object_ref)
    )
    old_review = ReviewReportRecord.model_validate(store.read_object(old_review_ref).payload)
    protocol_ref = ObjectRef.model_validate(baseline["ledger_refs"]["protocols"][0])
    updated_review = old_review.model_copy(
        update={"covered_refs": (finding_ref, *new_claim_refs, local_run_ref, protocol_ref)}
    )
    store.commit_object(
        project_id=project.name,
        object_type="review.report",
        object_id=old_review.review_id,
        payload=updated_review.model_dump(mode="json"),
        dependencies=(finding_ref, *new_claim_refs, local_run_ref, protocol_ref),
        supersedes=old_review_ref,
        event_type="review.completed",
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    assert "G2_REPRODUCTION_OVERSTATED" in {
        item["code"] for item in readiness["findings"]
    }


def test_g2_request_binds_evidence_and_review_closure(
    guarded_demo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, project = guarded_demo
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "candidate"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    monkeypatch.chdir(repo)

    result = CliRunner().invoke(
        app,
        [
            "gate",
            "request",
            project.name,
            "G2",
            "--decision",
            "确认主张、审核、披露和候选包",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    packet_ref = ObjectRef.model_validate(payload["data"]["packet_ref"])
    packet = GateManager(LedgerStore(project)).read_packet(packet_ref)
    bound_types = {reference.object_type for reference in packet.dependency_closure}
    assert {
        "delivery.manifest",
        "claim",
        "evidence.card",
        "source",
        "experiment",
        "research.protocol",
        "review.finding",
        "review.report",
        "generation.trace",
        "writing.manuscript.en",
        "writing.manuscript.zh",
    } <= bound_types


def _current_trace(store: LedgerStore) -> tuple[ObjectRef, GenerationTrace]:
    reference = next(
        event.object_ref
        for event in reversed(store.events())
        if event.object_ref is not None
        and event.object_ref.object_type == "generation.trace"
        and store.is_current_reference(event.object_ref)
    )
    return reference, GenerationTrace.model_validate(store.read_object(reference).payload)


def test_generation_trace_requires_field_capture_and_bound_outputs(
    guarded_demo: tuple[Path, Path],
) -> None:
    _, project = guarded_demo
    _, trace = _current_trace(LedgerStore(project))
    raw = trace.model_dump(mode="json")
    raw["capture_status"].pop("model_configuration")
    with pytest.raises(ValueError, match="capture_status"):
        GenerationTrace.model_validate(raw)

    raw = trace.model_dump(mode="json")
    raw["output_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="output_sha256"):
        GenerationTrace.model_validate(raw)

    assert trace.output_sha256 == generation_output_digest(trace.output_artifact_refs)
    assert trace.reproducibility == "traceable_only/non_deterministic"


def test_generic_ledger_record_accepts_complete_generation_trace(
    guarded_demo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    _, trace = _current_trace(store)
    new_trace = trace.model_copy(update={"trace_id": new_id("trace")})
    source = project / "candidates" / "generation-trace.json"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps(new_trace.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )
    dependencies = (
        *new_trace.source_refs,
        *new_trace.run_refs,
        *new_trace.output_artifact_refs,
    )

    monkeypatch.chdir(repo)
    arguments = [
        "ledger",
        "record",
        project.name,
        "generation.trace",
        "candidates/generation-trace.json",
    ]
    for dependency in dependencies:
        arguments.extend(("--depends-on", dependency.object_id))
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    reference = ObjectRef.model_validate(
        json.loads(result.output)["data"]["object_ref"]
    )

    assert reference.object_type == "generation.trace"
    assert GenerationTrace.model_validate(store.read_object(reference).payload) == new_trace


def test_ai_disclosure_requires_current_generation_trace(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    trace_ref, trace = _current_trace(store)
    store.commit_object(
        project_id=project.name,
        object_type="generation.trace",
        object_id=trace.trace_id,
        payload=trace.model_dump(mode="json"),
        status=ArtifactStatus.WITHDRAWN,
        dependencies=store.read_object(trace_ref).dependencies,
        supersedes=trace_ref,
        event_type="generation.trace_withdrawn",
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    assert "G2_GENERATION_TRACE_MISSING" in {
        item["code"] for item in readiness["findings"]
    }


def test_generation_trace_rejects_stale_manuscript_output(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    manuscript = project / "paper" / "en" / "manuscript.md"
    manuscript.write_text(
        manuscript.read_text(encoding="utf-8") + "\nChanged after trace.\n",
        encoding="utf-8",
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    assert "G2_TRACE_OUTPUT_STALE" in {item["code"] for item in readiness["findings"]}


def test_generation_trace_dependency_closure_must_be_complete(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    trace_ref, trace = _current_trace(store)
    store.commit_object(
        project_id=project.name,
        object_type="generation.trace",
        object_id=trace.trace_id,
        payload=trace.model_dump(mode="json"),
        dependencies=trace.output_artifact_refs,
        supersedes=trace_ref,
        event_type="generation.trace_recorded",
    )

    readiness = assess_delivery_readiness(repo, project.name)

    assert readiness["ok"] is False
    assert "G2_TRACE_DEPENDENCY_MISSING" in {
        item["code"] for item in readiness["findings"]
    }


def test_paper_rejects_forged_run_trace_object_types(
    guarded_demo: tuple[Path, Path],
) -> None:
    repo, project = guarded_demo
    store = LedgerStore(project)
    run_ref = next(
        event.object_ref
        for event in reversed(store.events())
        if event.object_ref is not None
        and event.object_ref.object_type == "experiment"
        and store.is_current_reference(event.object_ref)
    )
    claim_refs = tuple(
        event.object_ref
        for event in store.events()
        if event.object_ref is not None
        and event.object_ref.object_type == "claim"
        and store.is_current_reference(event.object_ref)
    )
    run_object = store.read_object(run_ref)
    run = ExperimentRecord.model_validate(run_object.payload)
    forged_run = run.model_copy(
        update={"log_refs": (claim_refs[0],), "artifact_refs": (claim_refs[0],)}
    )
    forged_ref = store.commit_object(
        project_id=project.name,
        object_type="experiment",
        object_id=run.run_id,
        payload=forged_run.model_dump(mode="json"),
        dependencies=(*run_object.dependencies, *claim_refs),
        supersedes=run_ref,
        event_type="experiment.completed",
    )
    for claim_ref in claim_refs:
        claim_object = store.read_object(claim_ref)
        claim = ClaimRecord.model_validate(claim_object.payload)
        updated = claim.model_copy(update={"run_refs": (forged_ref,)})
        store.commit_object(
            project_id=project.name,
            object_type="claim",
            object_id=claim.claim_id,
            payload=updated.model_dump(mode="json"),
            dependencies=(*claim.evidence_refs, forged_ref),
            supersedes=claim_ref,
            event_type="claim.recorded",
        )

    result = validate_paper(repo, project.name)
    codes = {item["code"] for item in result["findings"]}

    assert "RUN_TRACE_TYPE_INVALID" in codes
    assert "RUN_RECORD_CARDINALITY_INVALID" in codes
