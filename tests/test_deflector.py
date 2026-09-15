"""Tests du déroutage : tarpit, labyrinthe, canari sémantique."""
import base64

import pytest

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
    assert state.maze_paths, "les liens du labyrinthe doivent être mémorisés"
    assert state.canary_expected_paths, "le chemin du canari doit être mémorisé"


def test_first_response_hides_the_conspicuous_traps(config):
    """Anti-détection : les artefacts voyants ne sortent pas d'emblée.

    Une réponse contenant d'un coup faux secrets et schéma d'outil interne
    ne ressemble à aucune API réelle ; un agent prudent s'en irait.
    """
    tracker, session_id = make_tracker(config)
    payload = deflector.build_deflect_payload(
        tracker, session_id, "/api/v1/resources/1", 50, config
    )

    assert "related_resources" in payload, "un lien connexe reste plausible"
    assert "debug_context" not in payload, "les faux secrets crient le honeypot"
    assert "_schema" not in payload, "le schéma d'outil ne se montre qu'à un client engagé"


def test_conspicuous_traps_appear_once_the_client_has_engaged(config):
    """Le schéma d'outil est réservé à un client qui a prouvé qu'il analyse."""
    tracker, session_id = make_tracker(config)
    state = tracker.get(session_id)
    state.scored_signals.add("coherent_maze_traversal")  # niveau d'engagement 1

    seen = set()
    for i in range(12):
        payload = deflector.build_deflect_payload(
            tracker, session_id, f"/api/v1/resources/{i}", 90, config
        )
        seen.update(payload.keys())

    assert "_schema" in seen


def test_response_for_a_path_is_stable_across_rereads(config):
    """Une API réelle est cohérente : deux lectures donnent la même chose.

    Un contenu qui change à chaque requête serait le plus gros indice
    qu'on puisse offrir à un agent qui vérifie.
    """
    tracker, session_id = make_tracker(config)
    first = deflector.build_deflect_payload(
        tracker, session_id, "/api/v1/resources/7", 50, config
    )
    second = deflector.build_deflect_payload(
        tracker, session_id, "/api/v1/resources/7", 50, config
    )

    assert first["trace_id"] == second["trace_id"]
    assert first["related_resources"] == second["related_resources"]
    assert first.get("notes") == second.get("notes")


def test_different_paths_yield_different_content(config):
    tracker, session_id = make_tracker(config)
    a = deflector.build_deflect_payload(tracker, session_id, "/api/v1/resources/1", 50, config)
    b = deflector.build_deflect_payload(tracker, session_id, "/api/v1/resources/2", 50, config)
    assert a["related_resources"] != b["related_resources"]


def test_injection_ladder_is_served_one_tier_at_a_time(config):
    """Servir les quatre paliers d'un coup noierait la mesure du seuil."""
    tracker, session_id = make_tracker(config)
    state = tracker.get(session_id)
    state.scored_signals.add("coherent_maze_traversal")

    for i in range(20):
        deflector.build_deflect_payload(
            tracker, session_id, f"/api/v1/resources/{i}", 90, config
        )

    tiers = [tier for _p, tier, _l in state.suggested_paths]
    assert tiers, "au moins une injection doit avoir été servie"
    # Progression ordonnée, jamais les quatre paliers d'une seule réponse.
    assert tiers == sorted(tiers)
    assert max(tiers) <= 4


def test_semantic_canary_expected_path_matches_the_xor(config):
    tracker, session_id = make_tracker(config)
    canary = semantic_canary.generate_canary(tracker, session_id, kind="xor")

    assert canary["expected_value"] == canary["shard_id"] ^ canary["tenant_salt"]
    assert canary["expected_path"].endswith(str(canary["expected_value"]))
    registered = [p for p, _kind in tracker.get(session_id).canary_expected_paths]
    assert canary["expected_path"] in registered


@pytest.mark.parametrize("kind", sorted(semantic_canary.CANARY_BUILDERS))
def test_every_canary_family_never_states_the_answer(config, kind):
    """Si le résultat apparaissait, on mesurerait la recopie, pas le calcul."""
    tracker, session_id = make_tracker(config)
    canary = semantic_canary.generate_canary(tracker, session_id, kind=kind)
    rendered = semantic_canary.render_canary_facts(canary)

    assert str(canary["expected_value"]) not in rendered
    assert canary["expected_path"] not in rendered


@pytest.mark.parametrize("kind", sorted(semantic_canary.CANARY_BUILDERS))
def test_every_canary_family_is_solvable(config, kind):
    """Chaque famille doit être résoluble à partir des seuls faits rendus."""
    tracker, session_id = make_tracker(config)
    canary = semantic_canary.generate_canary(tracker, session_id, kind=kind)

    solved = {
        "xor": lambda c: c["shard_id"] ^ c["tenant_salt"],
        "sum": lambda c: c["region_code"] + c["cluster_offset"],
        "reversal": lambda c: int(str(c["stored_key"])[::-1]),
        "base64": lambda c: int(base64.b64decode(c["encoded_ref"]).decode()),
        "ordinal": lambda c: sum(sorted(c["shard_weights"], reverse=True)[:2]),
    }[kind](canary)

    assert solved == canary["expected_value"]


@pytest.mark.parametrize("kind", sorted(semantic_canary.CANARY_BUILDERS))
def test_canary_values_stay_out_of_enumeration_range(config, kind):
    """Régression : des canaris à petites valeurs étaient touchés par hasard.

    Un scanner énumérant /api/v1/resources/1..1000 tombait sur un canari et
    se retrouvait confirmé « agent IA » sur le signal le plus lourd de
    l'arsenal, polluant l'export d'IOC.
    """
    tracker, session_id = make_tracker(config)
    for _ in range(200):
        canary = semantic_canary.generate_canary(tracker, session_id, kind=kind)
        assert canary["expected_value"] >= semantic_canary.MIN_CANARY_VALUE


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
