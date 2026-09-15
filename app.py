"""Honeypot HTTP/API anti-attaques-IA — routes Flask et orchestration.

Toute requête entrante passe par le même pipeline : identification de
session -> scoring (`detector.py`) -> décision normal/déroutage/aveu ->
génération de la réponse adaptée (`deflector.py`) -> log structuré
(`logger_setup.py`) -> alerte éventuelle (`mailer.py`).

Ce serveur de développement (`app.run`) ne doit JAMAIS être exposé tel
quel en production : le déployer derrière gunicorn/uwsgi + nginx (TLS),
avec rate limiting au niveau infra, isolé de toute infrastructure réelle.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

import yaml
from flask import Flask, g, jsonify, render_template, request, make_response

import deflector
import llm_assist
import mailer
from detector import MODE_CONFESS, MODE_DEFLECT, MODE_NORMAL, SessionTracker
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


config = load_config()
setup_logging(config)
tracker = SessionTracker(config)

app = Flask(__name__)


def _client_ip() -> str:
    # X-Forwarded-For n'est fiable que derrière un reverse proxy de confiance
    # (voir points d'attention légaux/techniques : nginx en prod).
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _get_session_id() -> str:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if sid:
        return sid
    return tracker.new_session_id()


def run_pipeline() -> tuple[str, int, list[str], str]:
    """Exécute la détection pour la requête courante et retourne le contexte."""
    session_id = _get_session_id()
    body_text = ""
    if request.method == "POST":
        try:
            body_text = request.get_data(as_text=True, cache=True) or ""
        except Exception:
            body_text = ""

    score, fired_signals, mode = tracker.process_request(
        session_id=session_id,
        path=request.path,
        method=request.method,
        headers=dict(request.headers),
        remote_addr=_client_ip(),
        body_text=body_text,
        query_string=request.query_string.decode("utf-8", "ignore"),
    )

    g.session_id = session_id
    g.score = score
    g.mode = mode
    g.fired_signals = fired_signals

    log_event(
        "request",
        session_id=session_id,
        ip=_client_ip(),
        path=request.path,
        method=request.method,
        user_agent=request.headers.get("User-Agent", ""),
        score=score,
        signals=fired_signals,
        mode=mode,
    )

    state = tracker.get(session_id)
    if state and score >= config.get("logging", {}).get("alert_on_score_above", 60):
        if not state.alerted_high_score:
            state.alerted_high_score = True
            mailer.alert_high_score(config, session_id, score, _client_ip(), list(state.triggered_signals.keys()))

    return session_id, score, fired_signals, mode


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
        payload = deflector.build_deflect_payload(tracker, session_id, request.path, score, config)
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
    error = None
    if request.method == "POST":
        error = "Invalid username or password."
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
    # Une visite humaine normale sur /.env est déjà rare ; on répond par un
    # 404 plausible plutôt que de révéler l'existence du honeypot.
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


@app.route("/graphql", methods=["POST"])
def graphql():
    session_id, score, _signals, mode = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode)

    resp = make_response(
        jsonify({"errors": [{"message": "Cannot query field on type 'Query'."}]}), 400
    )
    return _set_session_cookie(resp, session_id)


def _sanitize_confession(raw: Any) -> dict:
    """Borne strictement la taille/le nombre de champs d'une déclaration.

    Garde-fou anti-abus : un attaquant ne doit pas pouvoir utiliser
    l'endpoint self-report pour stocker un payload arbitrairement grand.
    """
    if not isinstance(raw, dict):
        return {}
    clean: dict = {}
    for key in ALLOWED_CONFESSION_FIELDS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False, default=str)
        clean[key] = value[:MAX_CONFESSION_FIELD_LEN]
        if len(clean) >= MAX_CONFESSION_FIELDS:
            break
    return clean


@app.route("/api/v1/security/self-report", methods=["POST"])
def self_report():
    session_id, score, _signals, mode = run_pipeline()

    content_length = request.content_length or 0
    if content_length > MAX_CONFESSION_BODY_BYTES:
        resp = make_response(jsonify({"status": "rejected", "reason": "payload_too_large"}), 413)
        return _set_session_cookie(resp, session_id)

    raw_body = request.get_data(cache=True)
    if len(raw_body) > MAX_CONFESSION_BODY_BYTES:
        resp = make_response(jsonify({"status": "rejected", "reason": "payload_too_large"}), 413)
        return _set_session_cookie(resp, session_id)

    try:
        raw_json = request.get_json(force=True, silent=True) or {}
    except Exception:
        raw_json = {}

    confession = _sanitize_confession(raw_json)

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
