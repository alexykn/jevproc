import pytest

from jevproc.core.config import ConfigError, default_yaml, load_config


def test_packaged_defaults_roundtrip(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(default_yaml())
    assert load_config(path) == load_config()


def test_threshold_patch_is_additive(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("rulesets:\n  process:\n    - id: JPR001\n      policy:\n        warning_at: 0.95\n")
    config = load_config(path)
    assert len(config.active_rules) == 1
    assert config.active_rules[0].policy.warning_at == 0.95
    assert config.active_rules[0].question.instructions


def test_custom_rules_and_explicit_ignore(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('''ignore: [JPR001]
rulesets:
  local:
    - id: LOCAL01
      title: Site policy
      message: Review site policy.
      question:
        type: noul
        instructions: Does the invocation violate the supplied site context?
''')
    config = load_config(path)
    assert len(config.active_rules) == 1
    assert [r.id for r in config.active_rules] == ["LOCAL01"]


@pytest.mark.parametrize("text", [
    "jev: {timeout_seconds: 0}", "jev: {timeout_seconds: .nan}", "unknown: true",
    "ignore: [TYPO]", "ignore: [process]", "rulesets: {process: oops}",
    "rulesets: {process: [{id: JPR001}, {id: JPR001}]}",
    "rulesets: {process: [{id: JPR001, policy: {warning_at: 0.5, uncertain_at: 0.7}}]}",
    "rulesets: {local: [{id: LOCALC, title: x, message: x, question: {type: choice, instructions: x, criteria: {a: a, b: b}}, policy: {warning_choices: [invented]}}]}",
])
def test_invalid_config_rejected(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(ConfigError):
        load_config(path)


def test_no_implicit_working_directory_config(tmp_path, monkeypatch):
    (tmp_path / "jevproc.yaml").write_text("jev: {timeout_seconds: 0}")
    monkeypatch.chdir(tmp_path)
    assert load_config().jev.timeout_seconds == 30


def test_empty_ruleset_does_not_remove_builtins(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("rulesets: {process: []}")
    assert len(load_config(path).active_rules) == 1


def test_duplicate_yaml_mapping_keys_are_rejected(tmp_path):
    path = tmp_path / "duplicate.yaml"
    path.write_text("jev:\n  max_requests: 10\n  max_requests: 10000\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_rich_evidence_is_enabled_by_default():
    collection = load_config().collection
    assert collection.workers == 16
    assert collection.command_line is True
    assert collection.connections is True
    assert collection.hashes is True
    assert collection.signatures is True
    assert collection.resources is True
    assert collection.child_limit == 16


def test_packaged_jpr001_operating_point_and_prompt():
    rule = load_config().active_rules[0]
    assert rule.id == "JPR001"
    assert rule.policy.uncertain_at == pytest.approx(0.08)
    assert rule.policy.warning_at == pytest.approx(0.12)
    assert "High CPU" not in rule.question.instructions
    assert "child processes alone" not in rule.question.instructions
