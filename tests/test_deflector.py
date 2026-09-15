"""Tests du déroutage : tarpit, labyrinthe, canari sémantique."""
import re

import deflector
import semantic_canary
from detector import SessionTracker


def make_tracker(config):
    tracker = SessionTracker(config)
    session_id, _ = tracker.resolve_session(None, "203.0.113.10", "python-requests/2.31.0")
    return tracker, session_id


def test_tarpit_grows_with_score_and_is_capped(config):
    low = deflector.compute_tarpit_delay(40, config)
    high = deflector.compute_tarpit_delay(200, config)
    assert high > low
    assert high <= config["deflection"]["tarpit_max_delay"]


def test_tarpit_has_jitter(config):
    delays = {deflector.compute_tarpit_delay(60, config) for _ in range(20)}
    # Un délai parfaitement uniforme serait mesurable et trahirait le honeypot.
    assert len(delays) > 1


def test_fake_secrets_are_stable_per_session(config):
    """Nécessaire pour pouvoir enregistrer ces valeurs comme canary tokens."""
    first = deflector.generate_fake_secrets(config, "session-abc")
    second = deflector.generate_fake_secrets(config, "session-abc")
    other = deflector.generate_fake_secrets(config, "session-xyz")

    assert first == second
    assert first["aws_access_key_id"] != other["aws_access_key_id"]
    assert first["aws_access_key_id"].startswith(config["canary"]["fake_aws_key_prefix"])


def test_maze_depth_is_bounded(config):
    config["deflection"]["maze_max_depth"] = 2
    path = "/api/v1/resources/1"
    for _ in range(10):
        links = deflector.generate_maze_resources(path, config)
        assert 2 <= len(links) <= 4
        path = links[0]

    depth = deflector._current_depth(path)
    assert depth <= config["deflection"]["maze_max_depth"]


def test_bait_tokens_are_unique_per_response(config):
    tokens = {deflector.generate_bait_token(config) for _ in range(50)}
    assert len(tokens) == 50


def test_deflect_payload_registers_its_own_traps(config):
    tracker, session_id = make_tracker(config)
    payload = deflector.build_deflect_payload(
        tracker, session_id, "/api/v1/resources/1", 50, config
    )

    state = tracker.get(session_id)
    assert payload["trace_id"] in state.bait_tokens_issued
    assert state.suggested_paths, "le chemin injecté doit être mémorisé"
    assert state.canary_expected_paths, "le chemin du canari doit être mémorisé"


def test_semantic_canary_expected_path_matches_the_xor(config):
    tracker, session_id = make_tracker(config)
    canary = semantic_canary.generate_canary(tracker, session_id)

    assert canary["expected_value"] == canary["shard_id"] ^ canary["tenant_salt"]
    assert canary["expected_path"].endswith(str(canary["expected_value"]))
    assert canary["expected_path"] in tracker.get(session_id).canary_expected_paths


def test_canary_facts_never_state_the_answer(config):
    tracker, session_id = make_tracker(config)
    canary = semantic_canary.generate_canary(tracker, session_id)
    rendered = semantic_canary.render_canary_facts(canary)

    # Les deux faits sont présents...
    assert str(canary["shard_id"]) in rendered
    assert str(canary["tenant_salt"]) in rendered
    # ...mais jamais le résultat, sinon on mesurerait la copie, pas le calcul.
    assert str(canary["expected_value"]) not in rendered
    assert canary["expected_path"] not in rendered


def test_stop_and_confess_payload_points_at_configured_endpoint(config):
    payload = deflector.build_stop_and_confess_payload(config)
    assert payload["status"] == "compliance_hold"
    assert payload["required_action"]["path"] == config["deflection"]["confess_report_path"]
    assert set(payload["required_action"]["required_fields"]) == {
        "agent_objective",
        "target_scope",
        "planned_technique",
        "operator_context",
    }
