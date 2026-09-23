"""Packaged YAML defaults plus explicit, additive user configuration."""

from importlib.resources import files
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal, TypeAlias

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class ConfigError(ValueError):
    pass


ConfigMap: TypeAlias = dict[str, object]


class UniqueSafeLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate mapping keys rather than silently changing policy."""

    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise yaml.YAMLError("configuration mapping key must be a scalar") from exc
            if duplicate:
                raise yaml.YAMLError("duplicate configuration mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class NoulQuestion(Settings):
    type: Literal["noul"]
    instructions: str = Field(min_length=1, max_length=12000)
    criteria: dict[str, str] | None = None

    @model_validator(mode="after")
    def labels(self) -> "NoulQuestion":
        if self.criteria is not None and set(self.criteria) != {"true", "false"}:
            raise ValueError("Noul criteria must use quoted 'true' and 'false' keys")
        return self


class ChoiceQuestion(Settings):
    type: Literal["choice"]
    instructions: str = Field(min_length=1, max_length=12000)
    criteria: dict[str, str] = Field(min_length=2, max_length=255)


class ScoreQuestion(Settings):
    type: Literal["score"]
    instructions: str = Field(min_length=1, max_length=12000)
    criteria: list[str] = Field(min_length=2, max_length=10)


Question = Annotated[NoulQuestion | ChoiceQuestion | ScoreQuestion, Field(discriminator="type")]
Source = Literal[
    "executable",
    "command_line",
    "connections",
    "ancestry",
    "children",
    "resources",
    "file",
    "signature",
    "hash",
]


class Policy(Settings):
    warning_at: float = Field(default=0.85, ge=0, le=1)
    uncertain_at: float = Field(default=0.60, ge=0, le=1)
    confidence_min: float = Field(default=0.70, ge=0, le=1)
    warning_choices: list[str] = Field(default_factory=list)
    legitimate_choices: list[str] = Field(default_factory=list)
    score_warning_at: float = Field(default=2, ge=0, le=9)
    score_uncertain_at: float = Field(default=1.5, ge=0, le=9)

    @model_validator(mode="after")
    def ordered(self) -> "Policy":
        if self.uncertain_at >= self.warning_at:
            raise ValueError("uncertain_at must be below warning_at")
        if self.score_uncertain_at >= self.score_warning_at:
            raise ValueError("score_uncertain_at must be below score_warning_at")
        return self


class Rule(Settings):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,31}$")
    title: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=1000)
    requires: list[Source] = Field(default_factory=list)
    question: Question
    policy: Policy = Field(default_factory=Policy)

    @model_validator(mode="after")
    def policy_matches_question(self) -> "Rule":
        if isinstance(self.question, ChoiceQuestion):
            labels = set(self.policy.warning_choices + self.policy.legitimate_choices)
            if not self.policy.warning_choices or not labels <= self.question.criteria.keys():
                raise ValueError("Choice policy must name valid warning_choices")
            if set(self.policy.warning_choices) & set(self.policy.legitimate_choices):
                raise ValueError("warning and legitimate choices must be disjoint")
        elif isinstance(self.question, ScoreQuestion):
            if self.policy.score_warning_at > len(self.question.criteria) - 1:
                raise ValueError("score threshold is outside the question scale")
        elif self.policy.warning_choices or self.policy.legitimate_choices:
            raise ValueError("choice labels are only supported for Choice questions")
        return self


class JevSettings(Settings):
    model: str = Field(default="jev-1.13.0", pattern=r"^jev-[A-Za-z0-9.\-]+$")
    concurrency: int = Field(default=16, ge=1, le=128)
    timeout_seconds: float = Field(default=30, ge=0.1, le=300)
    retries: int = Field(default=2, ge=0, le=8)
    requests_per_minute: float = Field(default=0, ge=0, le=100000)
    max_retry_delay: float = Field(default=30, ge=0, le=300)
    max_requests: int = Field(default=1000, ge=1, le=100000)


class CollectionSettings(Settings):
    max_processes: int = Field(default=2048, ge=1, le=10000)
    workers: int = Field(default=16, ge=1, le=64)
    ancestry_depth: int = Field(default=4, ge=0, le=8)
    connections: bool = True
    command_line: bool = True
    hashes: bool = True
    signatures: bool = True
    resources: bool = True
    resource_sample_seconds: float = Field(default=0.10, ge=0.05, le=1.0)
    child_limit: int = Field(default=16, ge=0, le=32)
    max_hash_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=1024 * 1024 * 1024)


class CacheSettings(Settings):
    enabled: bool = True
    ttl_seconds: float = Field(default=60, ge=0, le=3600)
    max_entries: int = Field(default=4096, ge=1, le=100000)


class Config(Settings):
    schema_version: Literal[1] = 1
    host_context: str = Field(
        default="General-purpose Unix workstation or server; purpose is not otherwise known.", max_length=8000
    )
    jev: JevSettings = Field(default_factory=JevSettings)
    collection: CollectionSettings = Field(default_factory=CollectionSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    rulesets: dict[str, list[Rule]]
    ignore: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def rule_identity(self) -> "Config":
        all_ids = [r.id for rules in self.rulesets.values() for r in rules]
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("rule IDs must be unique across rulesets")
        if len(all_ids) > 128:
            raise ValueError("at most 128 rules are supported")
        unknown = set(self.ignore) - set(all_ids) - self.rulesets.keys()
        if unknown:
            raise ValueError("ignore references an unknown rule or ruleset")
        if not self.active_rules:
            raise ValueError("at least one active rule is required")
        return self

    @property
    def active_rules(self) -> list[Rule]:
        return [
            r
            for name, rules in self.rulesets.items()
            if name not in self.ignore
            for r in rules
            if r.id not in self.ignore
        ]


def default_yaml() -> str:
    return files("jevproc").joinpath("data/default.yaml").read_text(encoding="utf-8")


def _string_mapping(value: object, message: str) -> ConfigMap:
    if not isinstance(value, dict):
        raise ConfigError(message)
    result: ConfigMap = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConfigError("configuration mapping keys must be strings")
        result[key] = item
    return result


def _unique_safe_load(value: str | bytes) -> object:
    loader = UniqueSafeLoader(value)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _merge(base: Mapping[str, object], override: Mapping[str, object]) -> ConfigMap:
    result: ConfigMap = dict(base)
    for key, value in override.items():
        old = result.get(key)
        if isinstance(old, dict) and isinstance(value, dict):
            result[key] = _merge(
                _string_mapping(old, "configuration section must be a mapping"),
                _string_mapping(value, "configuration section must be a mapping"),
            )
        else:
            result[key] = value
    return result


def load_config(path: Path | None = None) -> Config:
    """Load packaged defaults and only an explicitly selected operator override."""
    try:
        data = _string_mapping(_unique_safe_load(default_yaml()), "packaged configuration must be a YAML mapping")
        if path is not None:
            data = _apply_override(data, _read_override(path))
        return Config.model_validate(data)
    except (OSError, yaml.YAMLError, ValidationError, UnicodeError, RecursionError) as exc:
        # Config values may contain accidental secrets; report the failure type only.
        raise ConfigError(f"invalid or unreadable configuration ({type(exc).__name__})") from exc


def _read_override(path: Path) -> ConfigMap:
    with path.open("rb") as handle:
        raw = handle.read(262145)
    if len(raw) > 262144:
        raise ConfigError("configuration exceeds 256 KiB")
    return _string_mapping(_unique_safe_load(raw), "configuration must be a YAML mapping")


def _rule_mappings(value: object) -> list[ConfigMap]:
    if not isinstance(value, list):
        raise ConfigError("each ruleset must contain rule mappings with an id")
    rules: list[ConfigMap] = []
    for item in value:
        rule = _string_mapping(item, "each ruleset must contain rule mappings with an id")
        if not isinstance(rule.get("id"), str):
            raise ConfigError("each ruleset must contain rule mappings with an id")
        rules.append(rule)
    return rules


def _patch_rules(existing: object, patches: object) -> list[ConfigMap]:
    base_rules = _rule_mappings(existing)
    patch_rules = _rule_mappings(patches)
    if len({rule["id"] for rule in patch_rules}) != len(patch_rules):
        raise ConfigError("duplicate rule ID in a ruleset override")
    by_id = {str(rule["id"]): rule for rule in base_rules}
    for rule in patch_rules:
        rule_id = str(rule["id"])
        by_id[rule_id] = _merge(by_id.get(rule_id, {}), rule)
    return list(by_id.values())


def _apply_override(defaults: ConfigMap, override: ConfigMap) -> ConfigMap:
    additions = _string_mapping(override.get("rulesets", {}), "rulesets must be a mapping")
    default_rulesets = _string_mapping(defaults.get("rulesets", {}), "packaged rulesets must be a mapping")
    rulesets: ConfigMap = dict(default_rulesets)
    for name, rules in additions.items():
        rulesets[name] = _patch_rules(default_rulesets.get(name, []), rules)
    settings = {key: value for key, value in override.items() if key != "rulesets"}
    return _merge({**defaults, "rulesets": rulesets}, settings)
