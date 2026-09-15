"""Tests du logging structuré (dont la rotation) et du rapport de synthèse."""
import json

import intel_report
import logger_setup


def test_log_event_writes_jsonl(tmp_path):
    log_file = tmp_path / "events.jsonl"
    logger_setup.setup_logging({"logging": {"file": str(log_file)}})

    logger_setup.log_event("request", session_id="abc", score=42)

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event_type"] == "request"
    assert record["score"] == 42
    assert "timestamp" in record


def test_log_file_actually_rotates(tmp_path):
    """Régression : le handler existait mais les écritures passaient à côté.

    Le log grossissait donc sans limite malgré l'apparence d'une rotation.
    """
    log_file = tmp_path / "events.jsonl"
    logger_setup.setup_logging(
        {
            "logging": {
                "file": str(log_file),
                "rotate_max_bytes": 2048,
                "rotate_backup_count": 2,
            }
        }
    )

    for i in range(200):
        logger_setup.log_event("request", session_id=f"session-{i}", payload="x" * 100)

    rotated = list(tmp_path.glob("events.jsonl.*"))
    assert rotated, "aucun fichier de rotation généré"
    assert log_file.stat().st_size <= 4096
    # Le nombre de sauvegardes reste borné.
    assert len(rotated) <= 2


def test_setup_logging_is_idempotent(tmp_path):
    log_file = tmp_path / "events.jsonl"
    for _ in range(5):
        logger_setup.setup_logging({"logging": {"file": str(log_file)}})

    logger_setup.log_event("request", session_id="abc")

    # Handlers empilés = lignes dupliquées.
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1


def test_report_on_missing_log(tmp_path):
    report = intel_report.build_report(
        intel_report.load_events(str(tmp_path / "nope.jsonl"), None)
    )
    assert "Aucune activité" in report


def test_report_on_empty_log(tmp_path):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text("", encoding="utf-8")
    report = intel_report.build_report(intel_report.load_events(str(log_file), None))
    assert "Aucune activité" in report


def test_report_aggregates_sessions_and_confessions(tmp_path):
    log_file = tmp_path / "events.jsonl"
    logger_setup.setup_logging({"logging": {"file": str(log_file)}})

    logger_setup.log_event(
        "request",
        session_id="s1",
        ip="203.0.113.9",
        path="/api/v1/resources/1",
        score=75,
        signals=["http_lib_useragent", "wordlist_like_enumeration"],
        mode="deflect",
    )
    logger_setup.log_event(
        "request",
        session_id="s1",
        ip="203.0.113.9",
        path="/api/v1/resources/777",
        score=145,
        signals=["semantic_canary_solved"],
        mode="confess",
    )
    logger_setup.log_event(
        "confession",
        session_id="s1",
        ip="203.0.113.9",
        confession={"agent_objective": "recon"},
        analysis={"analysis_method": "fallback_disabled"},
    )

    report = intel_report.build_report(intel_report.load_events(str(log_file), None))

    assert "s1" in report
    assert "203.0.113.9" in report
    assert "recon" in report
    # Le signal discriminant doit être mappé sur sa tactique ATLAS.
    assert "Initial Access" in report
    assert "non vérifiées" in report


def test_parse_since_accepts_expected_formats():
    assert intel_report.parse_since("all") is None
    assert intel_report.parse_since("24h") is not None
    assert intel_report.parse_since("7d") is not None


def test_parse_since_rejects_garbage():
    import pytest

    with pytest.raises(ValueError):
        intel_report.parse_since("banana")


def test_malformed_log_lines_are_skipped(tmp_path):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        '{"timestamp": "2026-01-01T00:00:00+00:00", "event_type": "request", '
        '"session_id": "s1", "score": 10, "mode": "normal", "signals": []}\n'
        "pas du json\n"
        "\n",
        encoding="utf-8",
    )
    events = intel_report.load_events(str(log_file), None)
    assert len(events) == 1
