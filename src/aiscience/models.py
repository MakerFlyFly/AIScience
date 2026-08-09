"""Versioned data contracts used by the AIScience ledger.

The models in this module deliberately describe facts that can be persisted.  Policy
and I/O live in :mod:`aiscience.state`, :mod:`aiscience.gates`, and
:mod:`aiscience.storage` respectively.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION: Literal["1.0"] = "1.0"
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}_[0-9a-z]{12,40}$")
PROJECT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Create a stable, sortable-enough identifier without leaking local data."""

    if not re.fullmatch(r"[a-z][a-z0-9_]{0,15}", prefix):
        raise ValueError("ID prefix must be lowercase ASCII")
    millis = int(utc_now().timestamp() * 1_000)
    return f"{prefix}_{millis:010x}{secrets.token_hex(5)}"


class FrozenModel(BaseModel):
    """Strict immutable base for persisted records."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_assignment=True)


class ProjectStage(StrEnum):
    RECEIVED = "received"
    CHARTER_LOCKED = "charter_locked"
    DESIGNING = "designing"
    LITERATURE_REVIEW = "literature_review"
    PROTOCOL_LOCKED = "protocol_locked"
    EXPERIMENTING = "experimenting"
    ANALYZING = "analyzing"
    WRITING = "writing"
    REVIEWING = "reviewing"
    DELIVERY_READY = "delivery_ready"
    DELIVERED = "delivered"


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    FAILED = "failed"
    PARTIAL = "partial"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class ArtifactStatus(StrEnum):
    ACTIVE = "active"
    FROZEN = "frozen"
    STALE = "stale"
    BLOCKED = "blocked"
    FAILED = "failed"
    PARTIAL = "partial"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class RunStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    FAILED = "failed"
    PARTIAL = "partial"
    INPUT_UNAVAILABLE = "input_unavailable"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class ReproductionLevel(StrEnum):
    FULL = "full"
    LOCAL_ONLY = "local_only"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class GateKind(StrEnum):
    G0 = "G0"
    G1 = "G1"
    G2 = "G2"


class GateDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class CaptureStatus(StrEnum):
    OBSERVED = "observed"
    DECLARED = "declared"
    UNKNOWN = "unknown"


class ResourceControl(StrEnum):
    HARD = "hard"
    BEST_EFFORT = "best_effort"
    OBSERVED_ONLY = "observed_only"


class EvidenceRole(StrEnum):
    SUPPORTS = "supports"
    REFUTES = "refutes"
    BACKGROUND = "background"


class ClaimType(StrEnum):
    NOVELTY = "novelty"
    QUANTITATIVE = "quantitative"
    COMPARATIVE = "comparative"
    CAUSAL = "causal"
    GENERALIZATION = "generalization"
    SAFETY = "safety"
    BACKGROUND = "background"
    OTHER = "other"


class SupportStatus(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    MIXED = "mixed"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"
    INSUFFICIENT = "insufficient"


class HypothesisAction(StrEnum):
    GENERATED = "generated"
    REFLECTED = "reflected"
    RANKED = "ranked"
    EVOLVED = "evolved"
    ELIMINATED = "eliminated"


class ReviewSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProjectPayload(FrozenModel):
    """Common invariants for typed ledger payloads."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    project_id: str

    @field_validator("project_id")
    @classmethod
    def validate_project_id(cls, value: str) -> str:
        if not PROJECT_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid project id")
        return value

    @model_validator(mode="after")
    def validate_record_identity_and_time(self) -> ProjectPayload:
        id_fields = (
            "record_id",
            "source_id",
            "card_id",
            "claim_id",
            "hypothesis_id",
            "analysis_id",
            "protocol_id",
            "run_id",
            "finding_id",
            "review_id",
            "trace_id",
            "manifest_id",
        )
        for field_name in id_fields:
            value = getattr(self, field_name, None)
            if value is not None and not ID_PATTERN.fullmatch(str(value)):
                raise ValueError(f"{field_name} is not a stable prefixed id")
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            if isinstance(value, datetime):
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError(f"{field_name} must be timezone-aware UTC")
                if value.utcoffset() != UTC.utcoffset(value):
                    raise ValueError(f"{field_name} must use UTC")
        return self


class SearchRecord(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    record_id: str
    project_id: str
    query: str = Field(min_length=1)
    tools_or_databases: tuple[str, ...]
    queried_at: datetime = Field(default_factory=utc_now)
    filters: dict[str, Any] = Field(default_factory=dict)
    ranking_method: str
    stop_condition: str
    snapshot_summary_zh: str
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class SourceRecord(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    source_id: str
    project_id: str
    title: str
    doi: str | None = None
    arxiv_id: str | None = None
    url: str | None = None
    local_fixture: bool = False
    version_label: str
    access_level: str
    license: str
    retracted: bool = False
    correction_notes_zh: tuple[str, ...] = ()
    metadata_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    fulltext_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    search_snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def require_locator(self) -> SourceRecord:
        if not self.local_fixture and not any((self.doi, self.arxiv_id, self.url)):
            raise ValueError("a source requires DOI, arXiv id, URL, or local_fixture")
        return self


class EvidenceCard(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    card_id: str
    project_id: str
    source_ref: ObjectRef
    paraphrase_zh: str = Field(min_length=1)
    locator: str = Field(min_length=1, description="Page, section, figure, or table locator")
    role: EvidenceRole
    limitations_zh: tuple[str, ...] = ()
    abstract_only: bool = False


class ClaimRecord(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    claim_id: str
    project_id: str
    canonical_text_en: str = Field(min_length=1)
    reader_text_zh: str = Field(min_length=1)
    claim_type: ClaimType
    evidence_refs: tuple[ObjectRef, ...] = ()
    run_refs: tuple[ObjectRef, ...] = ()
    support_status: SupportStatus
    limitations_zh: tuple[str, ...] = ()
    canonical_version: int = Field(ge=1)
    canonical_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    zh_based_on_version: int = Field(ge=1)
    zh_based_on_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_canonical_hash(self) -> ClaimRecord:
        actual = hashlib.sha256(self.canonical_text_en.encode("utf-8")).hexdigest()
        if self.canonical_text_sha256 != actual:
            raise ValueError("canonical_text_sha256 does not match canonical_text_en")
        return self

    @property
    def translation_stale(self) -> bool:
        return (
            self.canonical_version != self.zh_based_on_version
            or self.canonical_text_sha256 != self.zh_based_on_sha256
        )

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Keep claim/hash invariants when callers evolve a claim."""

        if not update:
            return super().model_copy(update=update, deep=deep)
        data = self.model_dump(mode="python")
        data.update(update)
        return type(self).model_validate(data)


class HypothesisRecord(ProjectPayload):
    """One immutable node in the generation/reflection/ranking/evolution lineage."""

    hypothesis_id: str
    action: HypothesisAction
    statement_en: str = Field(min_length=1)
    statement_zh: str = Field(min_length=1)
    parent_refs: tuple[ObjectRef, ...] = ()
    evidence_refs: tuple[ObjectRef, ...] = ()
    run_refs: tuple[ObjectRef, ...] = ()
    reflection_zh: str = ""
    falsifiable_predictions_zh: tuple[str, ...] = ()
    discriminating_experiments_zh: tuple[str, ...] = ()
    relative_rank: int | None = Field(default=None, ge=1)
    rank_basis_zh: str = ""
    elimination_reason_zh: str = ""
    negative_result_zh: str = ""

    @model_validator(mode="after")
    def validate_lineage_action(self) -> HypothesisRecord:
        if self.action is not HypothesisAction.GENERATED and not self.parent_refs:
            raise ValueError("derived hypothesis nodes require at least one parent")
        if self.action is HypothesisAction.RANKED and (
            self.relative_rank is None or not self.rank_basis_zh
        ):
            raise ValueError("ranked hypothesis nodes require rank and rank basis")
        if self.action is HypothesisAction.ELIMINATED and not self.elimination_reason_zh:
            raise ValueError("eliminated hypothesis nodes require an elimination reason")
        return self


class AnalysisRecord(ProjectPayload):
    """Traceable statistical analysis and its prespecified safeguards."""

    analysis_id: str
    protocol_ref: ObjectRef
    run_refs: tuple[ObjectRef, ...] = Field(min_length=1)
    methods: tuple[str, ...] = Field(min_length=1)
    estimands: tuple[str, ...] = Field(min_length=1)
    multiplicity_control_zh: str
    missing_data_policy_zh: str
    assumption_checks_zh: tuple[str, ...] = ()
    results: dict[str, float] = Field(default_factory=dict)
    sensitivity_analyses_zh: tuple[str, ...] = ()
    deviations_zh: tuple[str, ...] = ()
    reproduction_level: ReproductionLevel


class ProtocolRecord(ProjectPayload):
    """A frozen protocol bound to the exact project-relative source bytes."""

    protocol_id: str
    source_path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen: Literal[True] = True
    demo_only: bool = False

    @field_validator("source_path")
    @classmethod
    def require_relative_source_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not path.parts or path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            raise ValueError("protocol source_path must be project-relative")
        return path.as_posix()


class ExperimentRecord(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: str
    project_id: str
    plan_ref: ObjectRef
    protocol_ref: ObjectRef
    data_refs: tuple[ObjectRef, ...]
    environment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    basis_commit: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-f]+$")
    command: tuple[str, ...] = Field(min_length=1)
    seeds: tuple[int, ...]
    hardware: dict[str, Any]
    status: RunStatus
    log_refs: tuple[ObjectRef, ...] = ()
    metrics: dict[str, float] = Field(default_factory=dict)
    artifact_refs: tuple[ObjectRef, ...] = ()
    deviations_zh: tuple[str, ...] = ()
    retry_of: ObjectRef | None = None
    resource_controls: dict[str, ResourceControl]
    reproduction_level: ReproductionLevel


class ReviewFinding(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    finding_id: str
    project_id: str
    severity: ReviewSeverity
    category: str
    description_zh: str
    affected_refs: tuple[ObjectRef, ...] = ()
    disposition: str = "open"
    rationale_zh: str = ""


class ReviewReportRecord(ProjectPayload):
    """Delivery-facing review conclusion with an explicit audited scope."""

    review_id: str
    status: Literal["failed", "passed", "passed_for_delivery", "passed_for_demo_candidate"]
    risk_counts: dict[Literal["high", "medium", "low"], int]
    covered_refs: tuple[ObjectRef, ...] = Field(min_length=1)
    findings: tuple[dict[str, Any], ...] = ()
    reproducibility: ReproductionLevel
    demo_only: bool = False

    @field_validator("risk_counts", mode="before")
    @classmethod
    def validate_risk_counts(cls, value: Any) -> Any:
        if (
            not isinstance(value, dict)
            or set(value) != {"high", "medium", "low"}
            or any(type(count) is not int or count < 0 for count in value.values())
        ):
            raise ValueError("risk_counts must contain non-negative high, medium, and low counts")
        return value

    @model_validator(mode="after")
    def isolate_demo_review_status(self) -> ReviewReportRecord:
        demo_namespace = self.project_id.startswith("demo-")
        if self.demo_only != demo_namespace:
            raise ValueError("demo_only review reports are restricted to demo-* projects")
        if self.status == "passed_for_demo_candidate" and not demo_namespace:
            raise ValueError("demo review status is forbidden for formal projects")
        return self


class CapturedConfigurationValue(FrozenModel):
    """One instruction/model configuration value with explicit provenance."""

    status: CaptureStatus
    value: Any | None = None

    @model_validator(mode="after")
    def validate_capture(self) -> CapturedConfigurationValue:
        if self.status is CaptureStatus.UNKNOWN and self.value is not None:
            raise ValueError("unknown configuration values must not invent a value")
        if self.status is not CaptureStatus.UNKNOWN and self.value is None:
            raise ValueError("observed or declared configuration values require a value")
        return self


def generation_output_digest(references: Iterable[ObjectRef]) -> str:
    """Bind a generation event to an ordered set of immutable output objects."""

    values = tuple(references)
    if not values:
        raise ValueError("generation output references may not be empty")
    material = "\n".join(
        f"{ref.object_type}\0{ref.object_id}\0{ref.version}\0{ref.sha256}" for ref in values
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


_GENERATION_CAPTURE_FIELDS = frozenset(
    {
        "role",
        "input_summary_redacted_zh",
        "instruction_commit",
        "instruction_configuration",
        "model_configuration",
        "source_refs",
        "run_refs",
        "tool_trace",
        "output_artifact_refs",
        "output_sha256",
    }
)


class GenerationTrace(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    trace_id: str
    project_id: str
    role: str
    input_summary_redacted_zh: str
    instruction_commit: str | None = None
    instruction_configuration: dict[str, CapturedConfigurationValue] = Field(min_length=1)
    model_configuration: dict[str, CapturedConfigurationValue] = Field(min_length=1)
    source_refs: tuple[ObjectRef, ...] = ()
    run_refs: tuple[ObjectRef, ...] = ()
    tool_trace: tuple[dict[str, Any], ...] = ()
    output_artifact_refs: tuple[ObjectRef, ...] = Field(min_length=1)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capture_status: dict[str, CaptureStatus]
    reproducibility: Literal["traceable_only/non_deterministic"] = (
        "traceable_only/non_deterministic"
    )

    @model_validator(mode="after")
    def validate_trace_capture_and_outputs(self) -> GenerationTrace:
        missing = _GENERATION_CAPTURE_FIELDS - self.capture_status.keys()
        if missing:
            raise ValueError(
                "capture_status must cover every generation field: " + ", ".join(sorted(missing))
            )
        expected = generation_output_digest(self.output_artifact_refs)
        if self.output_sha256 != expected:
            raise ValueError("output_sha256 does not bind output_artifact_refs")
        return self


class ManifestEntry(FrozenModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    license: str | None = None

    @field_validator("path")
    @classmethod
    def require_relative_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not path.parts or path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            raise ValueError("manifest paths must be project-relative")
        return path.as_posix()


class DeliveryManifest(ProjectPayload):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    manifest_id: str
    project_id: str
    basis_commit: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-f]+$")
    gate_record_ref: ObjectRef
    reproduction_level: ReproductionLevel
    entries: tuple[ManifestEntry, ...]


class ObjectRef(FrozenModel):
    """Content-addressed reference to an immutable object ledger version."""

    object_id: str
    object_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    version: int = Field(ge=1)
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("object_id")
    @classmethod
    def validate_object_id(cls, value: str) -> str:
        if not ID_PATTERN.fullmatch(value):
            raise ValueError("invalid stable object id")
        return value

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("path must be project-relative and may not traverse parents")
        if ":" in path.parts[0]:
            raise ValueError("drive-qualified paths are forbidden")
        return path.as_posix()


class LedgerObject(FrozenModel):
    """Immutable object envelope; payload schemas may evolve independently."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    project_id: str
    object_id: str
    object_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    version: int = Field(ge=1)
    supersedes: ObjectRef | None = None
    created_at: datetime = Field(default_factory=utc_now)
    status: ArtifactStatus = ArtifactStatus.ACTIVE
    dependencies: tuple[ObjectRef, ...] = ()
    anchor_event_id: str
    payload: dict[str, Any]

    @field_validator("project_id")
    @classmethod
    def validate_project_id(cls, value: str) -> str:
        if not PROJECT_ID_PATTERN.fullmatch(value):
            raise ValueError("project_id must be a safe lowercase path component")
        return value

    @field_validator("object_id", "anchor_event_id")
    @classmethod
    def validate_stable_id(cls, value: str) -> str:
        if not ID_PATTERN.fullmatch(value):
            raise ValueError("invalid stable id")
        return value

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_lineage(self) -> LedgerObject:
        if self.version == 1 and self.supersedes is not None:
            raise ValueError("version 1 cannot supersede another version")
        if self.version > 1:
            if self.supersedes is None:
                raise ValueError("versions greater than 1 must declare supersedes")
            if (
                self.supersedes.object_id != self.object_id
                or self.supersedes.object_type != self.object_type
                or self.supersedes.version != self.version - 1
            ):
                raise ValueError(
                    "supersedes must reference the immediately previous object version"
                )
        return self


class EventRecord(FrozenModel):
    """A process fact stored in the append-only hash-chained event stream."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: str
    project_id: str
    event_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]{0,95}$")
    timestamp: datetime = Field(default_factory=utc_now)
    previous_hash: str = Field(pattern=r"^(?:[0-9a-f]{64})?$")
    object_ref: ObjectRef | None = None
    dependency_edges: tuple[ObjectRef, ...] = ()
    payload: dict[str, Any] = Field(default_factory=dict)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str) -> str:
        if not ID_PATTERN.fullmatch(value):
            raise ValueError("invalid event id")
        return value

    @field_validator("project_id")
    @classmethod
    def validate_project_id(cls, value: str) -> str:
        if not PROJECT_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid project id")
        return value

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)


class GatePacket(FrozenModel):
    """Chinese human-review packet bound to a dependency closure."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    packet_id: str
    project_id: str
    gate: GateKind
    created_at: datetime = Field(default_factory=utc_now)
    basis_commit: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-f]+$")
    decisions_zh: tuple[str, ...]
    changes_zh: tuple[str, ...] = ()
    risks_zh: tuple[str, ...] = ()
    budget_zh: tuple[str, ...] = ()
    alternatives_zh: tuple[str, ...] = ()
    open_questions_zh: tuple[str, ...] = ()
    invalidation_conditions_zh: tuple[str, ...] = ()
    dependency_roots: tuple[ObjectRef, ...] = ()
    dependency_closure: tuple[ObjectRef, ...] = ()
    reproduction_level: ReproductionLevel | None = None

    @field_validator("packet_id")
    @classmethod
    def validate_packet_id(cls, value: str) -> str:
        if not ID_PATTERN.fullmatch(value):
            raise ValueError("invalid packet id")
        return value

    @field_validator("project_id")
    @classmethod
    def validate_project_id(cls, value: str) -> str:
        if not PROJECT_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid project id")
        return value

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)


class GateRecord(FrozenModel):
    """Human decision.  This is auditable soft trust, not identity proof."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    record_id: str
    project_id: str
    gate: GateKind
    packet_ref: ObjectRef
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: GateDecision
    approver: str = Field(min_length=1, max_length=200)
    decided_at: datetime = Field(default_factory=utc_now)
    basis_commit: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-f]+$")
    approved_dependencies: tuple[ObjectRef, ...]
    accept_limited_reproduction: bool = False
    note_zh: str = ""

    @field_validator("record_id")
    @classmethod
    def validate_record_id(cls, value: str) -> str:
        if not ID_PATTERN.fullmatch(value):
            raise ValueError("invalid gate record id")
        return value

    @field_validator("project_id")
    @classmethod
    def validate_project_id(cls, value: str) -> str:
        if not PROJECT_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid project id")
        return value

    @field_validator("decided_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)


class IntegrityIssue(FrozenModel):
    code: str
    message_zh: str
    path: str | None = None


class IntegrityReport(FrozenModel):
    ok: bool
    event_count: int = Field(ge=0)
    object_count: int = Field(ge=0)
    issues: tuple[IntegrityIssue, ...] = ()
