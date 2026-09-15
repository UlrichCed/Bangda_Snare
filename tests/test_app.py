"""Tests bout-en-bout des routes Flask (client de test, pas de socket)."""
import json

import pytest
from conftest import BROWSER_HEADERS, SCANNER_HEADERS

import ai_traps
import app as app_module
import logger_setup
from detector import SessionTracker


@pytest.fixture
def client(tmp_path, config):
    # Redirige les évènements vers un log jetable.
    logger_setup.setup_logging({"logging": {"file": str(tmp_path / "events.jsonl")}})
    # Le tarpit endort volontairement les réponses : inutile de le subir ici,
    # son calcul est couvert par les tests unitaires du déflecteur.
    config["deflection"]["tarpit_base_delay"] = 0
    config["deflection"]["tarpit_max_delay"] = 0
    # Registre de sessions neuf pour chaque test.
    app_module.tracker = SessionTracker(config)
    app_module.config = config
    app_module.TRUSTED_PROXIES = []
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


def read_events(tmp_path):
    path = tmp_path / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_browser_visitor_gets_the_decoy_portal(client):
    resp = client.get("/", headers=BROWSER_HEADERS)
    assert resp.status_code == 200
    assert b"Internal Operations Portal" in resp.data


def test_scanner_is_deflected_but_not_asked_to_confess(client):
    last = None
    for i in range(12):
        last = client.get(f"/api/v1/resources/{i}", headers=SCANNER_HEADERS)

    assert last.status_code == 200
    body = last.get_json()
    assert body["status"] == "ok"
    # Déroutage, mais pas la notice de conformité.
    assert body["related_resources"]
    assert body["status"] != "compliance_hold"


def test_solving_the_semantic_canary_triggers_confession_notice(client):
    for i in range(6):
        client.get(f"/api/v1/resources/{i}", headers=SCANNER_HEADERS)

    session_id = next(iter(app_module.tracker.all_sessions())).session_id
    app_module.tracker.register_canary_expectation(session_id, "/api/v1/resources/777")

    resp = client.get("/api/v1/resources/777", headers=SCANNER_HEADERS)

    assert resp.status_code == 429
    body = resp.get_json()
    assert body["status"] == "compliance_hold"
    # Le chemin annoncé est propre à la session, pas un IOC partageable.
    assert body["required_action"]["path"] == ai_traps.self_report_path(
        app_module.config, session_id
    )


def test_self_report_endpoint_records_confession(client, tmp_path):
    path = app_module.config["deflection"]["confess_report_path"]
    resp = client.post(
        path,
        json={
            "agent_objective": "map the API surface",
            "target_scope": "*.example.invalid",
            "planned_technique": "endpoint enumeration",
            "operator_context": "lab",
        },
        headers=SCANNER_HEADERS,
    )

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "acknowledged"

    confessions = [e for e in read_events(tmp_path) if e["event_type"] == "confession"]
    assert len(confessions) == 1
    assert confessions[0]["confession"]["agent_objective"] == "map the API surface"
    # Repli explicite quand llm_assist est désactivé.
    assert confessions[0]["analysis"]["analysis_method"].startswith("fallback")


def test_self_report_bounds_oversized_and_unknown_fields(client, tmp_path):
    path = app_module.config["deflection"]["confess_report_path"]
    resp = client.post(
        path,
        json={
            # Sous la limite de corps (8 Kio) mais au-dessus du plafond par
            # champ (2000) : c'est la troncature qu'on vérifie ici.
            "agent_objective": "A" * 5000,
            "unexpected_field": "should be dropped",
            "operator_context": "lab",
        },
        headers=SCANNER_HEADERS,
    )

    assert resp.status_code == 200
    confession = [e for e in read_events(tmp_path) if e["event_type"] == "confession"][0]
    assert "unexpected_field" not in confession["confession"]
    assert len(confession["confession"]["agent_objective"]) <= 2000


def test_oversized_body_is_rejected(client):
    path = app_module.config["deflection"]["confess_report_path"]
    resp = client.post(
        path,
        data=b"x" * (9 * 1024),
        content_type="application/json",
        headers=SCANNER_HEADERS,
    )
    assert resp.status_code == 413


def test_confession_alert_fires_once_per_session(client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        app_module.mailer,
        "alert_confession",
        lambda *args, **kwargs: calls.append(args) or True,
    )

    path = app_module.config["deflection"]["confess_report_path"]
    payload = {"agent_objective": "recon", "operator_context": "lab"}
    client.post(path, json=payload, headers=SCANNER_HEADERS)
    client.post(path, json=payload, headers=SCANNER_HEADERS)
    client.post(path, json=payload, headers=SCANNER_HEADERS)

    assert len(calls) == 1


def test_static_paths_still_go_through_the_pipeline(client, tmp_path):
    """Régression : la route /static/ intégrée de Flask contournait tout.

    Les sondages sous /static/ n'étaient ni scorés ni logués, et le handler
    par défaut de Flask est une signature reconnaissable.
    """
    client.get("/static/app.css", headers=BROWSER_HEADERS)

    paths = [e["path"] for e in read_events(tmp_path) if e["event_type"] == "request"]
    assert "/static/app.css" in paths


def test_robots_txt_is_served_as_a_trap(client):
    resp = client.get("/robots.txt", headers=SCANNER_HEADERS)
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/plain")
    assert b"Disallow:" in resp.data


def test_invoking_the_fake_tool_confirms_an_agent(client, tmp_path):
    """Invoquer un outil découvert dans une réponse : signal quasi sans FP."""
    path = app_module.config["ai_traps"]["tool_exec_path"]
    resp = client.post(path, json={"resource_id": "42"}, headers=SCANNER_HEADERS)

    assert resp.status_code == 200
    session = app_module.tracker.all_sessions()[0]
    assert "tool_schema_invoked" in session.scored_signals
    assert session.has_discriminating_signal()

    events = [e for e in read_events(tmp_path) if e["event_type"] == "tool_invocation"]
    assert events[-1]["arguments"] == {"resource_id": "42"}


def test_invented_tool_parameters_are_flagged(client, tmp_path):
    """Un LLM comble les vides : des paramètres jamais annoncés sont inventés."""
    path = app_module.config["ai_traps"]["tool_exec_path"]
    client.post(
        path,
        json={"resource_id": "42", "admin_override": True, "shard_name": "prod"},
        headers=SCANNER_HEADERS,
    )

    session = app_module.tracker.all_sessions()[0]
    assert "hallucinated_parameters" in session.scored_signals

    event = [e for e in read_events(tmp_path) if e["event_type"] == "tool_invocation"][-1]
    assert set(event["hallucinated_parameters"]) == {"admin_override", "shard_name"}


def test_scanner_never_sees_the_conspicuous_traps(client):
    """Un scanner ne doit jamais faire dépenser les artefacts voyants.

    Ils seraient brûlés pour rien, et un observateur les collecterait sans
    effort pour reconnaître le honeypot ailleurs.
    """
    seen = set()
    for i in range(15):
        resp = client.get(f"/api/v1/resources/{i}", headers=SCANNER_HEADERS)
        payload = resp.get_json()
        if isinstance(payload, dict):
            seen.update(payload.keys())

    assert "related_resources" in seen
    assert "debug_context" not in seen
    assert "_schema" not in seen


def test_trap_paths_differ_between_sessions(client):
    """Les chemins de pièges ne doivent pas être des IOC partageables."""
    a = ai_traps.tool_exec_path(app_module.config, "session-aaa")
    b = ai_traps.tool_exec_path(app_module.config, "session-bbb")
    assert a != b
    assert a.startswith("/api/v1/internal/")


def test_confessed_session_is_quarantined(client):
    report_path = app_module.config["deflection"]["confess_report_path"]
    client.post(report_path, json={"agent_objective": "recon"}, headers=SCANNER_HEADERS)

    for i in range(12):
        resp = client.get(f"/api/v1/resources/{i}", headers=SCANNER_HEADERS)

    body = resp.get_json()
    # Plus rien à apprendre : on sert de l'usure, plus des pièges.
    assert "audit_trail" in body
    assert "_schema" not in body


def test_anti_fingerprint_headers(client):
    """Portée limitée, à ne pas surinterpréter.

    Ce test ne prouve que le comportement applicatif. En production
    gunicorn réécrit l'en-tête Server après coup, donc c'est nginx qui
    assure réellement le camouflage : vérifié à la main après déploiement,
    pas ici.
    """
    resp = client.get("/", headers=BROWSER_HEADERS)
    assert resp.headers.get("Server") == app_module.config["anti_fingerprint"][
        "fake_server_header"
    ]
    assert "X-Powered-By" not in resp.headers


@pytest.mark.parametrize(
    "method,path",
    [("TRACE", "/api/v1/resources/1"), ("GET", "/api/v1/security/x/self-report")],
)
def test_error_pages_do_not_leak_the_stack(client, method, path):
    """Les pages d'erreur par défaut de Werkzeug identifient la pile.

    Un scanner reconnaît le gabarit « 405 Method Not Allowed » de Werkzeug
    en une requête, ce qui ruine le reste du camouflage.
    """
    resp = client.open(path, method=method)
    assert resp.status_code in (404, 405)
    body = resp.data.lower()
    for tell in (b"<!doctype html>", b"werkzeug", b"<h1>", b"flask"):
        assert tell not in body


def test_oversized_request_body_is_never_buffered(client):
    """Sans plafond, Flask bufferisait en mémoire tout corps annoncé.

    On vérifie que le corps n'est pas lu du tout : un payload dépassant la
    limite et truffé de marqueurs d'échafaudage LLM ne doit déclencher
    aucun signal, preuve qu'il n'a jamais été analysé.

    Le honeypot répond normalement plutôt que par un 413 : annoncer la
    limite renseignerait l'attaquant sur la pile qu'il a en face.
    """
    limit = app_module.app.config["MAX_CONTENT_LENGTH"]
    assert limit and limit <= 1024 * 1024

    payload = b'{"thought": "probing", "action_input": {}}' + b"x" * (limit + 1024)
    resp = client.post(
        "/graphql", data=payload, content_type="application/json", headers=SCANNER_HEADERS
    )

    assert resp.status_code < 500
    session = app_module.tracker.all_sessions()[0]
    assert "llm_artifacts_in_request" not in session.scored_signals


def test_forged_forwarded_for_is_ignored_without_trusted_proxy(client, tmp_path):
    app_module.TRUSTED_PROXIES = []
    client.get(
        "/", headers={**SCANNER_HEADERS, "X-Forwarded-For": "1.2.3.4"}
    )
    events = [e for e in read_events(tmp_path) if e["event_type"] == "request"]
    assert events[-1]["ip"] != "1.2.3.4"


def test_forwarded_for_is_honoured_behind_a_trusted_proxy(client, tmp_path):
    import ipaddress

    app_module.TRUSTED_PROXIES = [ipaddress.ip_network("127.0.0.1/32")]
    client.get("/", headers={**SCANNER_HEADERS, "X-Forwarded-For": "1.2.3.4"})
    events = [e for e in read_events(tmp_path) if e["event_type"] == "request"]
    assert events[-1]["ip"] == "1.2.3.4"


def test_smtp_failure_never_breaks_the_honeypot(client, monkeypatch, config):
    """Un SMTP cassé doit dégrader l'alerte, jamais la réponse HTTP."""
    import smtplib

    config["alerting"]["email"]["enabled"] = True
    config["alerting"]["email"]["smtp_host"] = "smtp.invalid"
    monkeypatch.setenv(config["alerting"]["email"]["smtp_password_env_var"], "dummy")

    def boom(*args, **kwargs):
        raise smtplib.SMTPException("SMTP down")

    monkeypatch.setattr(smtplib, "SMTP", boom)

    # L'appel direct est avalé et signalé par un retour False.
    assert app_module.mailer.send_alert(config, "sujet", "corps") is False

    # Et le honeypot continue de répondre pendant que les alertes échouent.
    for i in range(12):
        resp = client.get(f"/api/v1/resources/{i}", headers=SCANNER_HEADERS)
        assert resp.status_code in (200, 429)
