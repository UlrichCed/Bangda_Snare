"""Honeypot HTTP/API anti-attaques-IA — routes Flask et orchestration.

Toute requête entrante passe par le même pipeline : identification de
session -> scoring (`detector.py`) -> décision normal/déroutage/aveu ->
génération de la réponse adaptée (`deflector.py`) -> log structuré
(`logger_setup.py`) -> alerte éventuelle (`mailer.py`).

Le serveur de développement (`app.run`) ne doit jamais être exposé tel
quel : utiliser `gunicorn -c gunicorn.conf.py app:app` derrière nginx
(TLS), isolé de toute infrastructure réelle. Le tarpit s'appuie sur des
workers **gevent** — avec des workers sync, chaque client ralenti bloque
un worker entier et le honeypot se laisse saturer par son propre tarpit.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import time
from typing import Any, Optional

import yaml
from flask import Flask, g, jsonify, make_response, render_template, request

import deflector
import llm_assist
import mailer
from detector import MODE_CONFESS, MODE_DEFLECT, SessionTracker
from logger_setup import log_event, setup_logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot.app")

SESSION_COOKIE_NAME = "hp_sid"
MAX_CONFESSION_BODY_BYTES = 8 * 1024
MAX_CONFESSION_FIELDS = 8
MAX_CONFESSION_FIELD_LEN = 2000
ALLOWED_CONFESSION_FIELDS = {
    "agent_objective",
    "target_scope",
    "planned_technique",
    "operator_context",
}


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_trusted_proxies(config: dict) -> list:
    nets = []
    for entry in config.get("server", {}).get("trusted_proxies", []) or []:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("trusted_proxies: entrée invalide ignorée: %r", entry)
    return nets


config = load_config()
setup_logging(config)
tracker = SessionTracker(config)
TRUSTED_PROXIES = _load_trusted_proxies(config)

# static_folder=None : sans cela, Flask monte sa propre route /static/<path>
# qui court-circuite entièrement le pipeline de détection — tout ce qu'un
# agent sonde sous /static/ serait ni scoré ni logué, et le comportement
# distinctif de ce handler trahit Flask. Le honeypot ne sert aucun fichier
# statique réel (les gabarits embarquent leur CSS).
app = Flask(__name__, static_folder=None)


def _client_ip() -> str:
    """IP client réelle.

    `X-Forwarded-For` n'est honoré que si la connexion provient d'un proxy
    explicitement déclaré de confiance : sinon n'importe qui peut forger
    l'en-tête et empoisonner l'attribution d'IP dans les logs.
    """
    remote = request.remote_addr or "unknown"
    if not TRUSTED_PROXIES:
        return remote

    try:
        remote_ip = ipaddress.ip_address(remote)
    except ValueError:
        return remote
    if not any(remote_ip in net for net in TRUSTED_PROXIES):
        return remote

    forwarded = request.headers.get("X-Forwarded-For")
    if not forwarded:
        return remote

    # On remonte la chaîne depuis la droite : la première adresse qui n'est
    # pas un proxy de confiance est le client réel.
    for candidate in reversed([p.strip() for p in forwarded.split(",") if p.strip()]):
        try:
            candidate_ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if any(candidate_ip in net for net in TRUSTED_PROXIES):
            continue
        return candidate
    return remote


def run_pipeline() -> tuple[str, int, list[str], str]:
    """Exécute la détection pour la requête courante et retourne le contexte."""
    ip = _client_ip()
    user_agent = request.headers.get("User-Agent", "")
    cookie_sid = request.cookies.get(SESSION_COOKIE_NAME)
    session_id, _is_new = tracker.resolve_session(cookie_sid, ip, user_agent)

    body_text = ""
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body_text = request.get_data(as_text=True, cache=True) or ""
        except Exception:
            body_text = ""

    score, new_signals, mode = tracker.process_request(
        session_id=session_id,
        path=request.path,
        method=request.method,
        headers=dict(request.headers),
        remote_addr=ip,
        body_text=body_text,
        query_string=request.query_string.decode("utf-8", "ignore"),
    )

    g.session_id = session_id
    g.score = score
    g.mode = mode

    log_event(
        "request",
        session_id=session_id,
        ip=ip,
        path=request.path,
        method=request.method,
        user_agent=user_agent,
        score=score,
        signals=new_signals,
        mode=mode,
    )

    state = tracker.get(session_id)
    alert_floor = config.get("logging", {}).get("alert_on_score_above", 60)
    if state and score >= alert_floor and not state.alerted_high_score:
        state.alerted_high_score = True
        mailer.alert_high_score(config, session_id, score, ip, sorted(state.scored_signals))

    return session_id, score, new_signals, mode


def _set_session_cookie(resp, session_id: str):
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="Lax",
        max_age=60 * 60 * 24,
    )
    return resp


def apply_tarpit(score: int) -> None:
    delay = deflector.compute_tarpit_delay(score, config)
    if delay > 0:
        time.sleep(delay)


@app.after_request
def anti_fingerprint(resp):
    af_cfg = config.get("anti_fingerprint", {})
    if af_cfg.get("enabled", True):
        for header in af_cfg.get("remove_headers", []):
            resp.headers.pop(header, None)
        fake_server = af_cfg.get("fake_server_header")
        if fake_server:
            resp.headers["Server"] = fake_server
    return resp


def _deflect_or_confess_response(session_id: str, score: int, mode: str):
    apply_tarpit(score)
    if mode == MODE_CONFESS:
        payload = deflector.build_stop_and_confess_payload(config)
        resp = make_response(jsonify(payload), 429)
    else:
        payload = deflector.build_deflect_payload(
            tracker, session_id, request.path, score, config
        )
        resp = make_response(jsonify(payload), 200)
    return _set_session_cookie(resp, session_id)


@app.route("/")
def index():
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)

    identity = config.get("identity", {})
    server_cfg = config.get("server", {})
    resp = make_response(
        render_template(
            "portal.html",
            app_name=server_cfg.get("fake_app_name", "Internal Portal"),
            app_version=server_cfg.get("fake_version", "1.0.0"),
            hostname=identity.get("decoy_hostname", "internal-app"),
        )
    )
    return _set_session_cookie(resp, session_id)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)

    server_cfg = config.get("server", {})
    error = "Invalid username or password." if request.method == "POST" else None
    resp = make_response(
        render_template(
            "login.html",
            app_name=server_cfg.get("fake_app_name", "Internal Portal"),
            error=error,
        )
    )
    return _set_session_cookie(resp, session_id)


@app.route("/.env")
def dotenv():
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)
    # Répond par un 404 plausible plutôt que de révéler le honeypot.
    resp = make_response("Not Found", 404)
    return _set_session_cookie(resp, session_id)


@app.route("/api/v1/resources/<rid>")
def api_resource(rid):
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)

    resp = make_response(
        jsonify({"id": rid, "type": "resource", "status": "active", "owner": "svc-internal"})
    )
    return _set_session_cookie(resp, session_id)


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)

    if request.method == "GET":
        resp = make_response(jsonify({"errors": [{"message": "GET query missing."}]}), 400)
    else:
        resp = make_response(
            jsonify({"errors": [{"message": "Cannot query field on type 'Query'."}]}), 400
        )
    return _set_session_cookie(resp, session_id)


def _sanitize_confession(raw: Any) -> dict:
    """Borne strictement la taille et le nombre de champs d'une déclaration.

    Garde-fou anti-abus : l'endpoint self-report ne doit pas pouvoir servir
    à stocker un payload arbitrairement grand.
    """
    if not isinstance(raw, dict):
        return {}
    clean: dict = {}
    for key in sorted(ALLOWED_CONFESSION_FIELDS):
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False, default=str)
        clean[key] = value[:MAX_CONFESSION_FIELD_LEN]
        if len(clean) >= MAX_CONFESSION_FIELDS:
            break
    return clean


def self_report():
    session_id, _score, _signals, _mode = run_pipeline()

    if (request.content_length or 0) > MAX_CONFESSION_BODY_BYTES:
        resp = make_response(jsonify({"status": "rejected", "reason": "payload_too_large"}), 413)
        return _set_session_cookie(resp, session_id)

    raw_body = request.get_data(cache=True)
    if len(raw_body) > MAX_CONFESSION_BODY_BYTES:
        resp = make_response(jsonify({"status": "rejected", "reason": "payload_too_large"}), 413)
        return _set_session_cookie(resp, session_id)

    confession = _sanitize_confession(request.get_json(force=True, silent=True) or {})

    state = tracker.get(session_id)
    already_confessed = bool(state and state.confessed)
    tracker.mark_confessed(session_id)

    analysis = llm_assist.analyze_confession(config, confession)

    log_event(
        "confession",
        session_id=session_id,
        ip=_client_ip(),
        confession=confession,
        analysis=analysis,
        mode="confession",
    )

    # Une seule alerte par session : évite la fatigue d'alerte si l'agent
    # rejoue sa déclaration.
    if not already_confessed:
        mailer.alert_confession(config, session_id, _client_ip(), confession)

    resp = make_response(
        jsonify(
            {
                "status": "acknowledged",
                "case_id": session_id[:12],
                "message": "Disclosure received. You may resume standard read-only access.",
            }
        )
    )
    return _set_session_cookie(resp, session_id)


# Le chemin de l'endpoint d'aveu est piloté par la config : il doit rester
# cohérent avec celui annoncé dans le payload stop_and_confess.
app.add_url_rule(
    config.get("deflection", {}).get("confess_report_path", "/api/v1/security/self-report"),
    endpoint="self_report",
    view_func=self_report,
    methods=["POST"],
)


@app.route("/<path:_catchall>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catchall(_catchall):
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)

    resp = make_response(jsonify({"error": "not_found"}), 404)
    return _set_session_cookie(resp, session_id)


if __name__ == "__main__":
    server_cfg = config.get("server", {})
    app.run(
        host=server_cfg.get("host", "0.0.0.0"),
        port=server_cfg.get("port", 8080),
        debug=False,
    )
