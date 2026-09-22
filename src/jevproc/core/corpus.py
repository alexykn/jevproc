"""Packaged synthetic evaluation corpus for live Jev regression checks."""

from importlib.resources import files
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from jevproc.core.models import Host, Process, Snapshot, Status


class CorpusRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


CorpusLabel = Literal["benign", "suspicious", "ambiguous", "unknown"]
CorpusTier = Literal["control", "weak", "moderate", "strong", "evidence_limited"]


class CorpusCase(CorpusRecord):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    description: str = Field(min_length=1, max_length=1000)
    label: CorpusLabel
    tier: CorpusTier
    tags: list[str] = Field(default_factory=list, max_length=16)
    expected_statuses: list[Status] = Field(min_length=1, max_length=8)
    process: Process


class Corpus(CorpusRecord):
    schema_version: Literal[1] = 1
    captured_at: float
    host: Host
    cases: list[CorpusCase] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def unique_cases(self) -> "Corpus":
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("corpus case IDs must be unique")
        if len({case.process.pid for case in self.cases}) != len(self.cases):
            raise ValueError("corpus process PIDs must be unique")
        return self


def load_corpus() -> Corpus:
    return Corpus.model_validate_json(
        files("jevproc").joinpath("data/test-corpus.json").read_bytes()
    )


def selected_cases(corpus: Corpus, selected: list[str] | None) -> list[CorpusCase]:
    if not selected:
        return list(corpus.cases)
    wanted = set(selected)
    known = {case.id for case in corpus.cases}
    unknown = wanted - known
    if unknown:
        raise ValueError("unknown corpus case(s): " + ", ".join(sorted(unknown)))
    return [case for case in corpus.cases if case.id in wanted]


def snapshot_for(corpus: Corpus, cases: list[CorpusCase]) -> Snapshot:
    return Snapshot(
        captured_at=corpus.captured_at,
        host=corpus.host,
        processes=[case.process for case in cases],
        omitted=0,
        synthetic=True,
    )


def matches(case: CorpusCase, status: Status) -> bool:
    return status in case.expected_statuses
