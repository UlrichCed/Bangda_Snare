"""Tests de la corrélation de campagne et du dévoilement progressif."""
import pytest
from conftest import BROWSER_HEADERS, SCANNER_HEADERS

import correlation
import deflector
import trap_director
from detector import SessionTracker


# --- Signature de client -------------------------------------------------


def test_signature_survives_ip_and_user_agent_rotation():
    """Le point : elle doit tenir quand l'attaquant change d'identité."""
    base = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "User-Agent": "python-requests/2.31.0",
    }
    rotated = dict(base, **{"User-Agent": "curl/8.5.0"})

    assert correlation.client_signature(base) == correlation.client_signature(rotated)


def test_signature_differs_between_distinct_tooling():
    requests_like = {"Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"}
    browser_like = {
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "fr-FR",
        "Connection": "keep-alive",
    }
    assert correlation.client_signature(requests_like) != correlation.client_signature(browser_like)


# --- Registre de pièges --------------------------------------------------


def test_registry_ignores_reuse_by_the_owning_session():
    registry = correlation.TrapRegistry()
    registry.register("/api/v1/resources/4242", "session-a")
    assert registry.find_reused("/api/v1/resources/4242", "", "session-a") is None


def test_registry_detects_reuse_by_another_session():
    registry = correlation.TrapRegistry()
    registry.register("/api/v1/resources/4242", "session-a")
    found = registry.find_reused("/api/v1/resources/4242", "", "session-b")
    assert found == ("/api/v1/resources/4242", "session-a")


def test_registry_detects_a_token_replayed_in_a_query_string():
    registry = correlation.TrapRegistry()
    registry.register("bait_0123456789abcdef", "session-a")
    found = registry.find_reused("/x", "ref=bait_0123456789abcdef&p=1", "session-b")
    assert found == ("bait_0123456789abcdef", "session-a")


def test_registry_is_bounded():
    registry = correlation.TrapRegistry(max_entries=100)
    for i in range(1000):
        registry.register(f"/api/v1/resources/{i}", f"session-{i}")
    assert registry.size() <= 100


# --- Campagnes -----------------------------------------------------------


def test_campaign_is_transitive():
    campaigns = correlation.CampaignTracker()
    campaigns.link("a", "b")
    campaigns.link("b", "c")
    assert campaigns.members("a") == {"a", "b", "c"}
    assert campaigns.campaign_of("c") == campaigns.campaign_of("a")


def test_campaign_keeps_its_evidence_across_merges():
    campaigns = correlation.CampaignTracker()
    campaigns.link("a", "b", reason="trap_reuse:/x")
    campaigns.link("c", "d", reason="trap_reuse:/y")
    campaigns.link("b", "c", reason="trap_reuse:/z")

    evidence = campaigns.evidence("a")
    assert {"trap_reuse:/x", "trap_reuse:/y", "trap_reuse:/z"} <= evidence
    assert campaigns.members("d") == {"a", "b", "c", "d"}


def test_only_multi_session_campaigns_are_reported():
    campaigns = correlation.CampaignTracker()
    campaigns.link("solo", "solo")
    campaigns.link("a", "b")
    reported = campaigns.campaigns()
    assert set(reported) == {campaigns.campaign_of("a")}


# --- Bout en bout : l'agent qui change d'identité entre deux requêtes -----


def test_identity_rotation_is_defeated_by_trap_reuse(config):
    """Le scénario d'évasion qui battait le scoring par session.

    L'agent lit une réponse sous une identité, puis enchaîne sous une
    autre : IP différente, UA différent, aucun cookie. Le canari qu'il
    rejoue ne peut venir que de la première session.
    """
    tracker = SessionTracker(config)

    first, _ = tracker.resolve_session(None, "203.0.113.1", "agent-alpha/1.0")
    tracker.process_request(first, "/api/v1/resources/1", "GET", SCANNER_HEADERS, "203.0.113.1")
    canary_path = "/api/v1/resources/7654321"
    tracker.register_canary_expectation(first, canary_path, "xor")

    # Rotation complète : autre IP, autre UA, pas de cookie.
    second, is_new = tracker.resolve_session(None, "198.51.100.77", "agent-beta/2.0")
    assert is_new and second != first

    _score, signals, mode = tracker.process_request(
        second, canary_path, "GET", {"User-Agent": "agent-beta/2.0"}, "198.51.100.77"
    )

    assert "cross_session_trap_reuse" in signals
    assert tracker.get(second).has_discriminating_signal()
    assert mode != "normal"
    # Les deux identités sont rattachées à une même campagne.
    assert tracker.campaigns.members(second) == {first, second}


def test_a_session_replaying_its_own_trap_is_not_a_campaign(config):
    """Garde anti-faux-positif : rejouer son propre piège n'est pas une rotation."""
    tracker = SessionTracker(config)
    sid, _ = tracker.resolve_session(None, "203.0.113.1", "agent/1.0")
    tracker.process_request(sid, "/api/v1/resources/1", "GET", SCANNER_HEADERS, "203.0.113.1")
    tracker.register_canary_expectation(sid, "/api/v1/resources/7654321", "xor")

    _score, signals, _mode = tracker.process_request(
        sid, "/api/v1/resources/7654321", "GET", SCANNER_HEADERS, "203.0.113.1"
    )

    assert "semantic_canary_solved" in signals
    assert "cross_session_trap_reuse" not in signals
    assert tracker.campaigns.campaigns() == {}


# --- Directeur de pièges -------------------------------------------------


def test_engagement_level_reflects_what_was_proven(config):
    tracker = SessionTracker(config)
    sid, _ = tracker.resolve_session(None, "203.0.113.1", "agent/1.0")
    state = tracker.get(sid)

    assert trap_director.engagement_level(state) == 0
    state.scored_signals.add("coherent_maze_traversal")
    assert trap_director.engagement_level(state) == 1
    state.scored_signals.add("semantic_canary_solved")
    assert trap_director.engagement_level(state) == 2


def test_director_throttles_but_never_starves_an_inert_client(config):
    """Ralentir, pas couper.

    Chaque canari occupe une entrée du registre global qu'un scanner
    massif saturerait, mais couper entièrement priverait de toute prise
    un agent qui se met à lire tardivement, et c'est le canari qui
    rattrape la rotation d'identité.
    """
    tracker = SessionTracker(config)
    sid, _ = tracker.resolve_session(None, "203.0.113.1", "scanner/1.0")
    state = tracker.get(sid)

    for i in range(60):
        deflector.build_deflect_payload(tracker, sid, f"/api/v1/resources/{i}", 50, config)

    canaries = state.traps_deployed.get(trap_director.TRAP_CANARY, 0)
    assert canaries > 0, "le canari ne doit jamais être coupé"
    assert canaries < 60, "mais sa cadence doit être réduite"
    # Les pièges voyants restent hors de portée d'un client non engagé.
    assert trap_director.TRAP_TOOL_SCHEMA not in state.traps_deployed
    assert trap_director.TRAP_SECRETS not in state.traps_deployed


def test_director_can_be_disabled_for_comparison(config):
    config["trap_director"]["enabled"] = False
    tracker = SessionTracker(config)
    sid, _ = tracker.resolve_session(None, "203.0.113.1", "agent/1.0")

    payload = deflector.build_deflect_payload(tracker, sid, "/api/v1/resources/1", 50, config)
    assert "_schema" in payload
    assert "debug_context" in payload
