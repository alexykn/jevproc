"""Versioned, bounded snapshot/report contracts. Unknown is distinct from absent."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Coverage = Literal["observed", "partial", "denied", "unavailable", "not_requested", "truncated", "gone"]
Status = Literal["warning", "uncertain_warning", "probably_legitimate", "no_warning", "unknown", "not_applicable", "not_evaluated"]
Text = Annotated[str, Field(max_length=8192)]
Name = Annotated[str, Field(max_length=512)]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class Connection(Record):
    protocol: Literal["tcp", "udp"]
    local_address: Name = ""
    local_port: int = Field(default=0, ge=0, le=65535)
    remote_address: Name = ""
    remote_port: int = Field(default=0, ge=0, le=65535)
    status: Name = ""


class Parent(Record):
    pid: int = Field(ge=0)
    created_at: float = Field(ge=0)
    name: Name
    executable: Text | None = None


class ResourceUsage(Record):
    cpu_percent: float | None = Field(default=None, ge=0, le=10000)
    rss_bytes: int | None = Field(default=None, ge=0)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    thread_count: int | None = Field(default=None, ge=0)
    fd_count: int | None = Field(default=None, ge=0)


class Child(Record):
    pid: int = Field(ge=0)
    created_at: float | None = Field(default=None, ge=0)
    name: Name = "<unavailable>"
    executable: Text | None = None
    status: Name = "unknown"


class Executable(Record):
    exists: bool | None = None
    size: int | None = Field(default=None, ge=0)
    mode: int | None = Field(default=None, ge=0)
    owner_uid: int | None = Field(default=None, ge=0)
    modified_ns: int | None = None
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    deleted: bool | None = None
    signature: Literal["valid", "verification_failed", "unavailable", "not_requested"] = "not_requested"
    signature_identifier: Name | None = None
    signature_team_id: Name | None = None
    signature_authorities: list[Name] = Field(default_factory=list, max_length=8)


class Process(Record):
    pid: int = Field(ge=0)
    created_at: float | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    uid: int | None = Field(default=None, ge=0)
    name: Name = "<unavailable>"
    executable: Text | None = None
    status: Name = "unknown"
    age_band: Literal["under_minute", "under_hour", "under_day", "older", "unknown"] = "unknown"
    command_line: list[Name] | None = Field(default=None, max_length=64)
    connections: list[Connection] = Field(default_factory=list, max_length=128)
    ancestors: list[Parent] = Field(default_factory=list, max_length=8)
    children: list[Child] = Field(default_factory=list, max_length=32)
    child_count: int = Field(default=0, ge=0)
    resources: ResourceUsage = Field(default_factory=ResourceUsage)
    file: Executable = Field(default_factory=Executable)
    coverage: dict[str, Coverage] = Field(default_factory=dict, max_length=20)
    observations: list[Name] = Field(default_factory=list, max_length=32)
    freshness: Literal["observed", "gone", "reused", "changed", "unverified"] = "observed"

    @property
    def ref(self) -> str:
        return f"p{self.pid}"


class Host(Record):
    platform: Literal["linux", "darwin", "fixture"]
    architecture: Name = "unknown"
    privileged: bool = False


class Snapshot(Record):
    schema_version: Literal[1] = 1
    captured_at: float = Field(ge=0, le=253402300799)
    host: Host
    processes: list[Process] = Field(max_length=10000)
    omitted: int = Field(default=0, ge=0)
    synthetic: bool = False

    @model_validator(mode="after")
    def unique_processes(self) -> "Snapshot":
        if len({p.pid for p in self.processes}) != len(self.processes):
            raise ValueError("snapshot contains duplicate PIDs")
        return self


class RuleResult(Record):
    rule: str
    title: str
    status: Status
    message: str = ""
    value: float | str | None = None
    probability: float | None = None
    confidence: float | None = None
    answer: dict = Field(default_factory=dict)


class Assessment(Record):
    process: Process
    status: Status
    rules: list[RuleResult] = Field(default_factory=list)
    cached: bool = False
    model: str | None = None
    error: str | None = None


class Report(Record):
    schema_version: Literal[1] = 1
    mode: Literal["live", "offline", "demo"]
    snapshot_time: float
    model_requested: str
    assessments: list[Assessment]
    summary: dict
