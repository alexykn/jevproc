"""Packaged YAML defaults plus explicit, additive user configuration."""

from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class ConfigError(ValueError):
    pass


type ConfigMap = dict[str, object]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


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
        labels = {"true", "false"} if self.criteria is None else set(self.criteria)
        _require(labels == {"true", "false"}, "Noul criteria must use quoted 'true' and 'false' keys")
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
        _require(self.uncertain_at < self.warning_at, "uncertain_at must be below warning_at")
        _require(self.score_uncertain_at < self.score_warning_at, "score_uncertain_at must be below score_warning_at")
        return self


def _validate_choice_policy(question: ChoiceQuestion, policy: Policy) -> None:
    warning = set(policy.warning_choices)
    legitimate = set(policy.legitimate_choices)
    labels = warning | legitimate
    _require(bool(warning), "Choice policy must name valid warning_choices")
    _require(labels <= question.criteria.keys(), "Choice policy must name valid warning_choices")
    _require(warning.isdisjoint(legitimate), "warning and legitimate choices must be disjoint")


def _validate_score_policy(question: ScoreQuestion, policy: Policy) -> None:
    _require(policy.score_warning_at <= len(question.criteria) - 1, "score threshold is outside the question scale")


def _validate_noul_policy(policy: Policy) -> None:
    _require(not any((policy.warning_choices, policy.legitimate_choices)), "choice labels are only supported for Choice questions")


def _validate_question_policy(question: Question, policy: Policy) -> None:
    if isinstance(question, ChoiceQuestion):
        _validate_choice_policy(question, policy)
    elif isinstance(question, ScoreQuestion):
        _validate_score_policy(question, policy)
    else:
        _validate_noul_policy(policy)


class Rule(Settings):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,31}$")
    title: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=1000)
    requires: list[Source] = Field(default_factory=list)
    question: Question
    policy: Policy = Field(default_factory=Policy)

    @model_validator(mode="after")
    def policy_matches_question(self) -> "Rule":
        _validate_question_policy(self.question, self.policy)
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


def _rule_ids(rulesets: dict[str, list[Rule]]) -> list[str]:
    return [rule.id for rules in rulesets.values() for rule in rules]


def _validate_rule_ids(all_ids: list[str]) -> None:
    _require(len(all_ids) == len(set(all_ids)), "rule IDs must be unique across rulesets")
    _require(len(all_ids) <= 128, "at most 128 rules are supported")


def _validate_ignore(ignore: list[str], all_ids: list[str], rulesets: dict[str, list[Rule]]) -> None:
    unknown = set(ignore).difference(all_ids, rulesets.keys())
    _require(not unknown, "ignore references an unknown rule or ruleset")


def _active_ruleset(name: str, rules: list[Rule], ignored: set[str]) -> list[Rule]:
    return [] if name in ignored else [rule for rule in rules if rule.id not in ignored]


def _active_rules(rulesets: dict[str, list[Rule]], ignore: list[str]) -> list[Rule]:
    ignored = set(ignore)
    return [
        rule
        for name, rules in rulesets.items()
        for rule in _active_ruleset(name, rules, ignored)
    ]


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
        all_ids = _rule_ids(self.rulesets)
        _validate_rule_ids(all_ids)
        _validate_ignore(self.ignore, all_ids, self.rulesets)
        _require(bool(self.active_rules), "at least one active rule is required")
        return self

    @property
    def active_rules(self) -> list[Rule]:
        return _active_rules(self.rulesets, self.ignore)


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


def _rule_mapping(item: object) -> ConfigMap:
    rule = _string_mapping(item, "each ruleset must contain rule mappings with an id")
    if not isinstance(rule.get("id"), str):
        raise ConfigError("each ruleset must contain rule mappings with an id")
    return rule


def _rule_mappings(value: object) -> list[ConfigMap]:
    if not isinstance(value, list):
        raise ConfigError("each ruleset must contain rule mappings with an id")
    return list(map(_rule_mapping, value))


def _patch_ids(rules: list[ConfigMap]) -> list[str]:
    ids = [str(rule["id"]) for rule in rules]
    if len(set(ids)) != len(ids):
        raise ConfigError("duplicate rule ID in a ruleset override")
    return ids


def _rule_index(rules: list[ConfigMap]) -> dict[str, ConfigMap]:
    return {str(rule["id"]): rule for rule in rules}


def _merged_rule_index(base_rules: list[ConfigMap], patch_rules: list[ConfigMap]) -> dict[str, ConfigMap]:
    by_id = _rule_index(base_rules)
    by_id.update({
        rule_id: _merge(by_id.get(rule_id, {}), rule)
        for rule_id, rule in zip(_patch_ids(patch_rules), patch_rules, strict=True)
    })
    return by_id


def _patch_rules(existing: object, patches: object) -> list[ConfigMap]:
    merged = _merged_rule_index(_rule_mappings(existing), _rule_mappings(patches))
    return list(merged.values())


def _apply_override(defaults: Mapping[str, object], override: Mapping[str, object]) -> ConfigMap:
    additions = _string_mapping(override.get("rulesets", {}), "rulesets must be a mapping")
    default_rulesets = _string_mapping(defaults.get("rulesets", {}), "packaged rulesets must be a mapping")
    rulesets: ConfigMap = dict(default_rulesets)
    for name, rules in additions.items():
        rulesets[name] = _patch_rules(default_rulesets.get(name, []), rules)
    settings = {key: value for key, value in override.items() if key != "rulesets"}
    return _merge({**defaults, "rulesets": rulesets}, settings)
