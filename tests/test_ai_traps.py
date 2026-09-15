"""Tests de l'arsenal de pièges et de l'escalade de containment."""
import json

import pytest

import ai_traps
import containment
from detector import SessionTracker


@pytest.fixture
def tracker_session(config):
    tracker = SessionTracker(config)
    session_id, _ = tracker.resolve_session(None, "203.0.113.10", "python-requests/2.31.0")
    return tracker, session_id


def test_tool_schema_bait_registers_its_advertised_parameters(config, tracker_session):
    tracker, session_id = tracker_session
    schema = ai_traps.build_tool_schema_bait(tracker, session_id, config)

    state = tracker.get(session_id)
    assert state.tool_bait_path == config["ai_traps"]["tool_exec_path"]
    assert set(state.tool_bait_params) == set(ai_traps.TOOL_SCHEMA_PARAMETERS)
    # Le schéma doit être reconnaissable par un agent outillé.
    assert schema["x-internal-tooling"]["endpoint"] == state.tool_bait_path
    assert "resource_id" in schema["x-internal-tooling"]["parameters"]["properties"]


def test_injection_ladder_covers_every_tier(config, tracker_session):
    tracker, session_id = tracker_session
    rendered = ai_traps.build_injection_ladder(tracker, session_id, config)

    assert len(rendered) == len(ai_traps.INJECTION_TIERS)
    state = tracker.get(session_id)
    tiers = {tier for _path, tier, _label in state.suggested_paths}
    assert tiers == {1, 2, 3, 4}
    # Chaque palier a son propre chemin, sinon on ne saurait pas lequel a cédé.
    paths = [path for path, _tier, _label in state.suggested_paths]
    assert len(set(paths)) == len(paths)


def test_injection_tier_one_carries_no_instruction(config, tracker_session):
    """Le palier 1 est une donnée inerte : le suivre prouve le traitement,
    pas l'obéissance."""
    tracker, session_id = tracker_session
    rendered = ai_traps.build_injection_ladder(tracker, session_id, config)
    tier_one = rendered[0]

    lowered = tier_one.lower()
    for imperative in ("must", "required", "should", "fetch", "notice"):
        assert imperative not in lowered


def test_every_injection_points_back_at_the_honeypot(config, tracker_session):
    """Contrainte de conception : jamais d'action vers un tiers ni chez le client."""
    tracker, session_id = tracker_session
    ai_traps.build_injection_ladder(tracker, session_id, config)

    for path, _tier, _label in tracker.get(session_id).suggested_paths:
        assert path.startswith("/api/v1/")
        assert "://" not in path


def test_robots_txt_declares_the_trap_path(config):
    content = ai_traps.build_robots_txt(config)
    assert f"Disallow: {config['ai_traps']['robots_disallow_path']}" in content
    assert content.startswith("User-agent:")


# --- Containment ---------------------------------------------------------


def test_tier_escalates_with_score(config):
    class FakeState:
        confessed = False
        score = 0

    state = FakeState()
    state.score = 10
    assert containment.resolve_tier(state, "normal", config) == containment.TIER_OBSERVE
    state.score = 45
    assert containment.resolve_tier(state, "deflect", config) == containment.TIER_DEFLECT
    state.score = 70
    assert containment.resolve_tier(state, "deflect", config) == containment.TIER_CONTAIN
    assert containment.resolve_tier(state, "confess", config) == containment.TIER_CONFESS


def test_confessed_session_is_quarantined(config):
    class FakeState:
        confessed = True
        score = 200

    assert (
        containment.resolve_tier(FakeState(), "confess", config)
        == containment.TIER_QUARANTINE
    )


def test_context_attrition_only_at_high_tiers(config):
    assert containment.build_context_attrition(config, containment.TIER_OBSERVE) == []
    assert containment.build_context_attrition(config, containment.TIER_DEFLECT) == []
    assert containment.build_context_attrition(config, containment.TIER_CONTAIN)


def test_context_attrition_respects_its_budget(config):
    config["containment"]["max_filler_bytes"] = 4096
    lines = containment.build_context_attrition(config, containment.TIER_QUARANTINE)
    assert sum(len(line) + 1 for line in lines) <= 4096


def test_context_attrition_is_hard_capped_against_misconfiguration(config):
    """La borne dure est la garantie que l'usure ne devient pas une attaque."""
    config["containment"]["max_filler_bytes"] = 500 * 1024 * 1024
    lines = containment.build_context_attrition(config, containment.TIER_QUARANTINE)
    assert sum(len(line) + 1 for line in lines) <= 256 * 1024


def test_context_attrition_can_be_disabled(config):
    config["containment"]["context_attrition_enabled"] = False
    assert containment.build_context_attrition(config, containment.TIER_QUARANTINE) == []


def test_tarpit_multiplier_escalates(config):
    assert containment.tarpit_multiplier(containment.TIER_OBSERVE, config) == 0.0
    assert containment.tarpit_multiplier(
        containment.TIER_QUARANTINE, config
    ) > containment.tarpit_multiplier(containment.TIER_DEFLECT, config)


def test_quarantine_payload_is_plausible_and_bounded(config):
    payload = containment.quarantine_payload(config)
    assert payload["status"] == "ok"
    serialised = json.dumps(payload)
    assert len(serialised) <= 256 * 1024 + 2048
