import json

import httpx
import pytest

import jevproc.cli.corpus as corpus_cli
from jevproc.core.calibration import calibration_report, describe, evaluate_pair, evaluate_samples
from jevproc.core.client import JevClient as RealJevClient
from jevproc.core.corpus import load_corpus, matches, selected_cases, snapshot_for


def test_packaged_corpus_shape_and_labels():
    corpus = load_corpus()
    assert len(corpus.cases) == 72
    assert len({case.id for case in corpus.cases}) == 72
    assert len({case.process.pid for case in corpus.cases}) == 72
    counts = {
        label: sum(case.label == label for case in corpus.cases)
        for label in ("benign", "suspicious", "ambiguous", "unknown")
    }
    assert counts == {"benign": 30, "suspicious": 25, "ambiguous": 10, "unknown": 7}
    assert corpus.host.platform == "fixture"


def test_corpus_matches_rich_default_evidence_profile():
    corpus = load_corpus()
    for case in corpus.cases:
        process = case.process
        if case.label == "unknown":
            assert process.coverage["hash"] == "unavailable"
            assert process.coverage["signature"] == "unavailable"
            assert process.coverage["command_line"] in {"denied", "unavailable"}
            assert process.coverage["resources"] == "unavailable"
            assert process.coverage["children"] == "unavailable"
            assert process.resources.cpu_percent is None
            continue
        assert process.command_line is not None
        assert process.coverage["command_line"] == "observed"
        assert process.coverage["connections"] == "observed"
        assert process.coverage["resources"] == "observed"
        assert process.coverage["children"] in {"observed", "truncated"}
        assert process.resources.cpu_percent is not None
        assert process.resources.rss_bytes is not None
        assert process.child_count >= len(process.children)
        if process.file.exists is True:
            assert process.file.sha256 is not None
            assert process.coverage["hash"] == "observed"
            if process.file.signature == "valid":
                assert process.file.signature_identifier
                assert process.file.signature_team_id
                assert process.file.signature_authorities
                assert process.coverage["signature"] == "observed"


def test_corpus_resources_do_not_encode_the_label():
    corpus = load_corpus()
    benign = {case.id: case.process for case in corpus.cases if case.label == "benign"}
    suspicious = {case.id: case.process for case in corpus.cases if case.label == "suspicious"}

    assert benign["benign-clang-build"].resources.cpu_percent > 100
    assert benign["benign-browser-renderer"].resources.rss_bytes > 1024 * 1024 * 1024
    assert suspicious["susp-world-writable-root-no-network"].resources.cpu_percent < 1
    assert suspicious["susp-temp-dropper-network"].resources.rss_bytes < 100 * 1024 * 1024

    assert benign["benign-container-runtime"].child_count > 0
    assert suspicious["susp-browser-shell-hidden-child"].child_count > 0


def test_corpus_evidence_limited_cases_are_internally_consistent():
    corpus = load_corpus()
    for case in corpus.cases:
        if case.label != "unknown":
            continue
        assert case.process.executable is None
        assert case.process.file.exists is None
        assert case.process.file.signature == "not_requested"
        assert case.process.coverage["executable"] != "observed"


def test_corpus_selection_and_snapshot():
    corpus = load_corpus()
    cases = selected_cases(corpus, ["susp-root-user-writable-masquerade", "benign-clang-build"])
    snapshot = snapshot_for(corpus, cases)
    assert snapshot.synthetic
    assert len(snapshot.processes) == 2
    with pytest.raises(ValueError, match="unknown corpus case"):
        selected_cases(corpus, ["does-not-exist"])


def test_match_policy_is_explicit():
    corpus = load_corpus()
    ambiguous = next(case for case in corpus.cases if case.id == "ambig-shell-from-ide")
    assert matches(ambiguous, "warning")
    assert matches(ambiguous, "uncertain_warning")
    assert matches(ambiguous, "probably_legitimate")
    assert matches(ambiguous, "no_warning")
    assert not matches(ambiguous, "unknown")

    suspicious = next(case for case in corpus.cases if case.label == "suspicious")
    assert matches(suspicious, "warning")
    assert matches(suspicious, "uncertain_warning")
    assert not matches(suspicious, "probably_legitimate")


def test_list_does_not_require_api_key(capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert corpus_cli.main(["--list", "--label", "suspicious"]) == 0
    text = capsys.readouterr().out
    assert "susp-root-user-writable-masquerade" in text
    assert "label=suspicious" in text
    assert "benign-clang-build" not in text


def _mock_client(monkeypatch, score_for_label):
    corpus = load_corpus()
    by_pid = {case.process.pid: case for case in corpus.cases}

    def transport():
        async def handler(request):
            payload = json.loads(request.content)
            process = payload["state"]["process"]
            case = by_pid[process["pid"]]
            value = score_for_label(case.label)
            answers = {
                key: {"type": "noul", "noul": value}
                for key in payload["questions"]
            }
            return httpx.Response(
                200,
                json={
                    "model": payload["model"],
                    "answers": answers,
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                },
            )

        return httpx.MockTransport(handler)

    def client(settings, api_key, *, base_url):
        return RealJevClient(
            settings,
            api_key or "test-key",
            base_url="http://localhost",
            transport=transport(),
        )

    monkeypatch.setattr(corpus_cli, "JevClient", client)
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-key")


def test_live_regression_harness_with_mock_provider(capsys, monkeypatch):
    _mock_client(
        monkeypatch,
        lambda label: {
            "suspicious": 0.95,
            "ambiguous": 0.65,
            "benign": 0.03,
            "unknown": 0.03,
        }[label],
    )
    assert corpus_cli.main(["--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["cases"] == 72
    assert result["summary"]["samples"] == 72
    assert result["summary"]["passed_samples"] == 72
    assert result["summary"]["mismatches"] == 0
    assert result["summary"]["requests"] == 72


def test_calibration_mode_measures_raw_scores_not_current_statuses(capsys, monkeypatch):
    _mock_client(
        monkeypatch,
        lambda label: {
            "suspicious": 0.30,
            "ambiguous": 0.12,
            "benign": 0.04,
            "unknown": 0.04,
        }[label],
    )
    # Calibration is observational even when the active policy classifies samples differently.
    assert corpus_cli.main(["--calibrate", "--runs", "2", "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["samples"] == 144
    assert result["summary"]["requests"] == 144
    calibration = result["calibration"]
    assert calibration["distributions"]["benign"]["mean"] == pytest.approx(0.04)
    assert calibration["distributions"]["ambiguous"]["mean"] == pytest.approx(0.12)
    assert calibration["distributions"]["suspicious"]["mean"] == pytest.approx(0.30)
    assert calibration["candidate_basis"] == "individual_samples"
    balanced = calibration["candidates"]["balanced"]
    assert 0.04 < balanced["uncertain_at"] <= 0.12
    assert 0.12 < balanced["warning_at"] <= 0.30
    assert balanced["exact_accuracy"] == 1
    assert balanced["benign_false_positive_rate"] == 0
    assert balanced["suspicious_warning_recall"] == 1
    assert balanced["suspicious_surface_recall"] == 1
    warnings_first = calibration["candidates"]["warnings_first"]
    assert warnings_first["benign_hard_warning_rate"] == 0
    assert warnings_first["suspicious_surface_recall"] == 1


def test_sample_level_calibration_does_not_hide_outliers_in_case_means():
    corpus = load_corpus()
    selected = [
        next(case for case in corpus.cases if case.label == "benign"),
        next(case for case in corpus.cases if case.label == "ambiguous"),
        next(case for case in corpus.cases if case.label == "suspicious"),
    ]
    samples = {
        selected[0].id: [0.04, 0.04, 0.11],
        selected[1].id: [0.08, 0.09, 0.10],
        selected[2].id: [0.08, 0.12, 0.30],
    }
    report = calibration_report(
        selected,
        samples,
        current_uncertain=0.08,
        current_warning=0.10,
    )

    # The benign case mean is below 0.10, but one real run crosses it.
    assert report["case_mean_candidates"]["current"]["benign_hard_warning_rate"] == 0
    assert report["candidates"]["current"]["benign_hard_warning_rate"] == pytest.approx(1 / 3)
    assert report["candidates"]["current"]["suspicious_surface_recall"] == 1
    assert report["separation"]["max_benign_sample"] == pytest.approx(0.11)
    assert report["separation"]["min_suspicious_sample"] == pytest.approx(0.08)

    cases = {case.id: case for case in selected}
    sample_metrics = evaluate_samples(samples, cases, uncertain_at=0.08, warning_at=0.12)
    assert sample_metrics.benign_hard_warning_rate == 0
    assert sample_metrics.suspicious_surface_recall == 1


def test_warnings_first_search_can_select_observed_boundaries():
    corpus = load_corpus()
    benign = next(case for case in corpus.cases if case.label == "benign")
    ambiguous = next(case for case in corpus.cases if case.label == "ambiguous")
    suspicious = next(case for case in corpus.cases if case.label == "suspicious")
    report = calibration_report(
        [benign, ambiguous, suspicious],
        {
            benign.id: [0.03, 0.08, 0.11],
            ambiguous.id: [0.06, 0.09, 0.14],
            suspicious.id: [0.08, 0.12, 0.30],
        },
        current_uncertain=0.08,
        current_warning=0.12,
    )
    candidate = report["candidates"]["warnings_first"]
    assert candidate["uncertain_at"] == pytest.approx(0.08)
    assert candidate["warning_at"] == pytest.approx(0.12)
    assert candidate["benign_hard_warning_rate"] == 0
    assert candidate["suspicious_surface_recall"] == 1


def test_calibration_requires_relevant_labels(capsys, monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "unused")
    assert corpus_cli.main(["--calibrate", "--label", "benign"]) == 2
    assert "requires at least one selected case" in capsys.readouterr().err


def test_calibration_statistics_and_pair_metrics():
    assert describe([0.02, 0.04, 0.06])["median"] == pytest.approx(0.04)

    corpus = load_corpus()
    selected = [
        next(case for case in corpus.cases if case.label == "benign"),
        next(case for case in corpus.cases if case.label == "ambiguous"),
        next(case for case in corpus.cases if case.label == "suspicious"),
    ]
    samples = {
        selected[0].id: [0.03, 0.05],
        selected[1].id: [0.11, 0.13],
        selected[2].id: [0.28, 0.32],
    }
    report = calibration_report(
        selected,
        samples,
        current_uncertain=0.60,
        current_warning=0.85,
    )
    assert report["separation"]["benign_to_ambiguous_gap"] > 0
    assert report["separation"]["benign_to_suspicious_gap"] > 0

    case_means = {case_id: sum(values) / len(values) for case_id, values in samples.items()}
    metrics = evaluate_pair(
        case_means,
        {case.id: case for case in selected},
        uncertain_at=0.08,
        warning_at=0.20,
    )
    assert metrics.exact_accuracy == 1
    assert metrics.benign_false_positive_rate == 0
    assert metrics.benign_hard_warning_rate == 0
    assert metrics.suspicious_surface_recall == 1
