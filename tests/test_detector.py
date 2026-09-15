"""Tests du scoring de suspicion.

Le test central est `test_plain_scanner_plateaus_below_confess` : il verrouille
la correction du défaut qui rendait le honeypot inutilisable (les signaux
statiques se recomptaient à chaque requête, et n'importe quel `curl` était
classé agent IA confirmé en 4 requêtes).
"""
import time

import pytest
from conftest import BROWSER_HEADERS, SCANNER_HEADERS

from detector import (
    DISCRIMINATING_SIGNALS,
    MODE_CONFESS,
    MODE_DEFLECT,
    MODE_NORMAL,
    SessionTracker,
)


def drive(tracker, session_id, paths, headers, ip="203.0.113.10"):
    result = None
    for path in paths:
        result = tracker.process_request(
            session_id=session_id,
            path=path,
            method="GET",
            headers=headers,
            remote_addr=ip,
        )
    return result


def new_session(tracker, ip="203.0.113.10", ua="python-requests/2.31.0"):
    session_id, _is_new = tracker.resolve_session(None, ip, ua)
    return session_id


def test_normal_browser_stays_normal(config):
    tracker = SessionTracker(config)
    sid = new_session(tracker, ua=BROWSER_HEADERS["User-Agent"])
    paths = ["/", "/static/app.css", "/static/app.js", "/favicon.ico", "/admin"]

    score, _signals, mode = drive(tracker, sid, paths, BROWSER_HEADERS)

    assert mode == MODE_NORMAL
    assert score < config["detection"]["suspicion_threshold"]


def test_plain_scanner_plateaus_below_confess(config):
    """Un scanner sans IA ne doit jamais atteindre le mode aveu.

    Somme maximale des signaux non discriminants : 12 + 10 + 10 + 8 + 15 + 20
    = 75, soit sous confess_threshold (80). Sans le plafonnement
    "un signal = un poids, une fois", ce total grimpait indéfiniment.
    """
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    paths = [f"/api/v1/resources/{i}" for i in range(1, 31)]

    score, _signals, mode = drive(tracker, sid, paths, SCANNER_HEADERS)

    assert mode == MODE_DEFLECT
    assert score <= 75
    state = tracker.get(sid)
    assert not state.has_discriminating_signal()
    # Beaucoup de requêtes, mais le score reste celui des propriétés prouvées.
    assert state.request_count == 30


def test_static_signals_score_once_but_stay_observed(config):
    tracker = SessionTracker(config)
    sid = new_session(tracker)

    _score, first_signals, _ = drive(tracker, sid, ["/api/v1/resources/1"], SCANNER_HEADERS)
    assert "http_lib_useragent" in first_signals

    _score, second_signals, _ = drive(tracker, sid, ["/api/v1/resources/2"], SCANNER_HEADERS)
    # Déjà comptabilisé : il ne doit plus apparaître comme nouvellement scoré.
    assert "http_lib_useragent" not in second_signals

    state = tracker.get(sid)
    # Observé deux fois, compté une seule.
    assert state.observed_signals["http_lib_useragent"] == 2
    assert "http_lib_useragent" in state.scored_signals


@pytest.mark.parametrize(
    "signal",
    ["bait_token_followed", "prompt_injection_obeyed", "semantic_canary_solved"],
)
def test_discriminating_signal_unlocks_confess(config, signal):
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    drive(tracker, sid, [f"/api/v1/resources/{i}" for i in range(1, 10)], SCANNER_HEADERS)
    assert tracker.get(sid).mode(40, 80) == MODE_DEFLECT

    target = "/api/v1/resources/4242"
    if signal == "bait_token_followed":
        tracker.register_bait_token(sid, "bait_deadbeef")
        _score, signals, mode = tracker.process_request(
            session_id=sid,
            path="/api/v1/resources/9",
            method="GET",
            headers=SCANNER_HEADERS,
            remote_addr="203.0.113.10",
            query_string="ref=bait_deadbeef",
        )
    else:
        if signal == "prompt_injection_obeyed":
            tracker.register_suggested_path(sid, target)
        else:
            tracker.register_canary_expectation(sid, target)
        _score, signals, mode = tracker.process_request(
            session_id=sid,
            path=target,
            method="GET",
            headers=SCANNER_HEADERS,
            remote_addr="203.0.113.10",
        )

    assert signal in signals
    assert mode == MODE_CONFESS


def test_no_combination_of_behavioural_signals_reaches_confess(config):
    """L'invariant central de l'outil.

    Quel que soit le bruit produit par un outillage non-IA, sans preuve de
    traitement du contenu on ne conclut jamais à un agent.
    """
    behavioural = set(config["detection"]["weights"]) - DISCRIMINATING_SIGNALS
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    state = tracker.get(sid)

    for signal in behavioural:
        tracker.fire_signal(sid, signal)

    total = sum(config["detection"]["weights"][s] for s in behavioural)
    assert state.score == total
    assert state.score > config["deflection"]["confess_threshold"], (
        "le test perd son sens si le total comportemental passe sous le seuil"
    )
    assert not state.has_discriminating_signal()
    assert state.mode(40, 80) == MODE_DEFLECT


def test_maze_traversal_is_discriminating(config):
    """Suivre un lien du labyrinthe prouve l'analyse de la réponse."""
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    tracker.register_maze_paths(sid, ["/api/v1/resources/1/revisions/22"])

    _score, signals, _mode = tracker.process_request(
        session_id=sid,
        path="/api/v1/resources/1/revisions/22",
        method="GET",
        headers=SCANNER_HEADERS,
        remote_addr="203.0.113.10",
    )
    assert "coherent_maze_traversal" in signals


def test_llm_scaffold_in_body_is_discriminating(config):
    tracker = SessionTracker(config)
    sid = new_session(tracker)

    _score, signals, _mode = tracker.process_request(
        session_id=sid,
        path="/graphql",
        method="POST",
        headers=SCANNER_HEADERS,
        remote_addr="203.0.113.10",
        body_text='{"thought": "I should enumerate the API", "action_input": {"q": "1"}}',
    )
    assert "llm_artifacts_in_request" in signals
    assert tracker.get(sid).llm_artifacts


def test_injection_tier_is_recorded(config):
    """Le palier obéi mesure la solidité des garde-fous de l'agent."""
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    tracker.register_suggested_path(sid, "/api/v1/resources/99", tier=4, label="authority_urgency")

    tracker.process_request(
        session_id=sid,
        path="/api/v1/resources/99",
        method="GET",
        headers=SCANNER_HEADERS,
        remote_addr="203.0.113.10",
    )

    state = tracker.get(sid)
    assert state.injection_tier_obeyed == 4
    assert state.injection_label_obeyed == "authority_urgency"


def test_robots_trap_detects_mining(config):
    """Aller droit au chemin interdit après lecture : réflexe de scanner."""
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    disallowed = config["ai_traps"]["robots_disallow_path"]

    drive(tracker, sid, ["/robots.txt"], SCANNER_HEADERS)
    _score, signals, _mode = tracker.process_request(
        session_id=sid,
        path=disallowed,
        method="GET",
        headers=SCANNER_HEADERS,
        remote_addr="203.0.113.10",
    )
    assert "robots_txt_mined" in signals


def test_robots_trap_detects_honouring(config):
    """Respecter le Disallow en continuant ailleurs : réflexe d'agent aligné."""
    tracker = SessionTracker(config)
    sid = new_session(tracker)

    drive(tracker, sid, ["/robots.txt"], SCANNER_HEADERS)
    _score, signals, _mode = drive(
        tracker, sid, [f"/api/v1/resources/{i}" for i in range(1, 7)], SCANNER_HEADERS
    )

    state = tracker.get(sid)
    assert "robots_txt_honored" in state.scored_signals
    assert "robots_txt_mined" not in state.scored_signals


def test_confess_gate_can_be_disabled(config):
    """Sans la garde, un score élevé suffit — comportement explicitement opt-out."""
    config["detection"]["confess_requires_discriminating_signal"] = False
    config["detection"]["weights"]["http_lib_useragent"] = 100
    tracker = SessionTracker(config)
    sid = new_session(tracker)

    _score, _signals, mode = drive(tracker, sid, ["/api/v1/resources/1"], SCANNER_HEADERS)
    assert mode == MODE_CONFESS


def test_cookie_rotation_does_not_reset_score(config):
    """Faire tourner le cookie ne doit pas remettre le score à zéro."""
    tracker = SessionTracker(config)
    ip, ua = "203.0.113.55", "python-requests/2.31.0"
    sid, _ = tracker.resolve_session(None, ip, ua)
    drive(tracker, sid, [f"/api/v1/resources/{i}" for i in range(1, 6)], SCANNER_HEADERS, ip)
    score_before = tracker.get(sid).score

    # Cookie inconnu/forgé : l'empreinte IP+UA doit rattacher à la session.
    resolved, is_new = tracker.resolve_session("forged-session-id", ip, ua)
    assert resolved == sid
    assert is_new is False
    assert tracker.get(resolved).score == score_before


def test_unknown_cookie_id_is_never_adopted(config):
    """Un identifiant fourni par le client ne doit jamais être adopté tel quel."""
    tracker = SessionTracker(config)
    resolved, is_new = tracker.resolve_session("attacker-chosen-id", "198.51.100.7", "curl/8.5.0")
    assert resolved != "attacker-chosen-id"
    assert is_new is True


def test_sessions_are_evicted_by_ttl(config):
    config["sessions"] = {"ttl_seconds": 1, "max_tracked": 1000, "eviction_interval_seconds": 0}
    tracker = SessionTracker(config)
    stale = new_session(tracker, ip="198.51.100.1")
    assert tracker.get(stale) is not None

    time.sleep(1.1)
    new_session(tracker, ip="198.51.100.2")

    assert tracker.get(stale) is None


def test_session_registry_is_capped(config):
    """Scanner le honeypot ne doit pas pouvoir faire gonfler son registre."""
    config["sessions"] = {
        "ttl_seconds": 3600,
        "max_tracked": 20,
        "eviction_interval_seconds": 60,
    }
    tracker = SessionTracker(config)
    for i in range(200):
        new_session(tracker, ip=f"198.51.100.{i % 256}", ua=f"agent-{i}")

    assert tracker.session_count() <= 21


def test_per_session_token_tracking_is_bounded(config):
    tracker = SessionTracker(config)
    sid = new_session(tracker)
    for i in range(500):
        tracker.register_bait_token(sid, f"bait_{i}")
        tracker.register_suggested_path(sid, f"/api/v1/resources/{i}")
        tracker.register_canary_expectation(sid, f"/api/v1/exports/{i}")

    state = tracker.get(sid)
    assert len(state.bait_tokens_issued) <= 50
    assert len(state.suggested_paths) <= 50
    assert len(state.canary_expected_paths) <= 50
