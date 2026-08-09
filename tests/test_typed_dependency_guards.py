from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiscience.models import (
    AnalysisRecord,
    CapturedConfigurationValue,
    CaptureStatus,
    EvidenceCard,
    EvidenceRole,
    ExperimentRecord,
    GenerationTrace,
    HypothesisAction,
    HypothesisRecord,
    ObjectRef,
    ReproductionLevel,
    ResourceControl,
    ReviewFinding,
    ReviewSeverity,
    RunStatus,
    generation_output_digest,
    new_id,
)
from aiscience.scaffold import record_typed_payload
from aiscience.storage import LedgerStore


def _object(store: LedgerStore, object_type: str) -> ObjectRef:
    return store.commit_object(
        project_id=store.project_id,
        object_type=object_type,
        payload={"fixture": True},
    )


def _candidate(project: Path, name: str, value: object) -> Path:
    path = project / "candidates" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _trace(
    project_id: str,
    source_ref: ObjectRef,
    run_ref: ObjectRef,
    output_ref: ObjectRef,
) -> GenerationTrace:
    return GenerationTrace(
        trace_id=new_id("trace"),
        project_id=project_id,
        role="writer",
        input_summary_redacted_zh="脱敏输入摘要",
        instruction_configuration={
            "workflow": CapturedConfigurationValue(
                status=CaptureStatus.DECLARED,
                value="evidence-first",
            )
        },
        model_configuration={"model": CapturedConfigurationValue(status=CaptureStatus.UNKNOWN)},
        source_refs=(source_ref,),
        run_refs=(run_ref,),
        output_artifact_refs=(output_ref,),
        output_sha256=generation_output_digest((output_ref,)),
        capture_status={
            "role": CaptureStatus.DECLARED,
            "input_summary_redacted_zh": CaptureStatus.DECLARED,
            "instruction_commit": CaptureStatus.UNKNOWN,
            "instruction_configuration": CaptureStatus.DECLARED,
            "model_configuration": CaptureStatus.UNKNOWN,
            "source_refs": CaptureStatus.OBSERVED,
            "run_refs": CaptureStatus.OBSERVED,
            "tool_trace": CaptureStatus.UNKNOWN,
            "output_artifact_refs": CaptureStatus.OBSERVED,
            "output_sha256": CaptureStatus.OBSERVED,
        },
    )


def test_hypothesis_analysis_generation_and_review_require_payload_edges(
    tmp_path: Path,
) -> None:
    project = tmp_path / "study-01"
    store = LedgerStore(project)
    parent = _object(store, "hypothesis")
    protocol = _object(store, "research.protocol")
    run = _object(store, "experiment")
    output = _object(store, "writing.manuscript.en")
    claim = _object(store, "claim")
    values = (
        (
            "hypothesis",
            HypothesisRecord(
                hypothesis_id=new_id("hypothesis"),
                project_id=project.name,
                action=HypothesisAction.REFLECTED,
                statement_en="A falsifiable hypothesis.",
                statement_zh="一个可证伪的假设。",
                parent_refs=(parent,),
            ),
        ),
        (
            "analysis",
            AnalysisRecord(
                analysis_id=new_id("analysis"),
                project_id=project.name,
                protocol_ref=protocol,
                run_refs=(run,),
                methods=("robust summary",),
                estimands=("RMSE",),
                multiplicity_control_zh="无多重检验",
                missing_data_policy_zh="不适用",
                reproduction_level=ReproductionLevel.FULL,
            ),
        ),
        ("generation.trace", _trace(project.name, claim, run, output)),
        (
            "review.finding",
            ReviewFinding(
                finding_id=new_id("finding"),
                project_id=project.name,
                severity=ReviewSeverity.LOW,
                category="fixture",
                description_zh="测试发现",
                affected_refs=(claim,),
            ),
        ),
    )
    for object_type, value in values:
        source = _candidate(project, f"{object_type.replace('.', '-')}.json", value)
        with pytest.raises(ValueError, match="dependencies"):
            record_typed_payload(
                project,
                project.name,
                source=source,
                object_type=object_type,
                dependencies=(),
            )


def test_typed_dependency_rejects_wrong_type_and_superseded_reference(
    tmp_path: Path,
) -> None:
    project = tmp_path / "study-01"
    store = LedgerStore(project)
    wrong_protocol = _object(store, "source")
    run = _object(store, "experiment")
    analysis = AnalysisRecord(
        analysis_id=new_id("analysis"),
        project_id=project.name,
        protocol_ref=wrong_protocol,
        run_refs=(run,),
        methods=("summary",),
        estimands=("mean",),
        multiplicity_control_zh="不适用",
        missing_data_policy_zh="不适用",
        reproduction_level=ReproductionLevel.FULL,
    )
    with pytest.raises(ValueError, match="对象类型错误"):
        record_typed_payload(
            project,
            project.name,
            source=_candidate(project, "analysis.json", analysis),
            object_type="analysis",
            dependencies=(wrong_protocol, run),
        )

    source_v1 = _object(store, "source")
    source_v2 = store.commit_object(
        project_id=project.name,
        object_type="source",
        object_id=source_v1.object_id,
        payload={"fixture": "new"},
        supersedes=source_v1,
    )
    assert source_v2.version == 2
    evidence = EvidenceCard(
        card_id=new_id("evcard"),
        project_id=project.name,
        source_ref=source_v1,
        paraphrase_zh="测试释义",
        locator="fixture",
        role=EvidenceRole.BACKGROUND,
    )
    with pytest.raises(ValueError, match="已失效对象"):
        record_typed_payload(
            project,
            project.name,
            source=_candidate(project, "evidence.json", evidence),
            object_type="evidence.card",
            dependencies=(source_v1,),
        )


def test_generic_typed_ledger_cannot_forge_an_experiment(tmp_path: Path) -> None:
    project = tmp_path / "study-01"
    store = LedgerStore(project)
    claim = _object(store, "claim")
    forged = ExperimentRecord(
        run_id="run_123456789abc",
        project_id=project.name,
        plan_ref=claim,
        protocol_ref=claim,
        data_refs=(),
        environment_sha256="0" * 64,
        basis_commit="1" * 40,
        command=("python", "forged.py"),
        seeds=(1,),
        hardware={},
        status=RunStatus.SUCCEEDED,
        log_refs=(claim,),
        artifact_refs=(claim,),
        resource_controls={"shell": ResourceControl.HARD},
        reproduction_level=ReproductionLevel.FULL,
    )

    with pytest.raises(ValueError, match="run execute"):
        record_typed_payload(
            project,
            project.name,
            source=_candidate(project, "forged-experiment.json", forged),
            object_type="experiment",
            dependencies=(claim,),
        )
