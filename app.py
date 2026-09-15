"""Honeypot HTTP/API anti-attaques-IA : routes Flask et orchestration.

Toute requête entrante passe par le même pipeline : identification de
session -> scoring (`detector.py`) -> décision normal/déroutage/aveu ->
génération de la réponse adaptée (`deflector.py`) -> log structuré
(`logger_setup.py`) -> alerte éventuelle (`mailer.py`).

Le serveur de développement (`app.run`) ne doit jamais être exposé tel
quel : utiliser `gunicorn -c gunicorn.conf.py app:app` derrière nginx
(TLS), isolé de toute infrastructure réelle. Le tarpit s'appuie sur des
workers **gevent** : avec des workers sync, chaque client ralenti bloque
un worker entier et le honeypot se laisse saturer par son propre tarpit.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import random
import time
from http import HTTPStatus
from typing import Any, Optional

import yaml
from flask import Flask, g, jsonify, make_response, render_template, request

import ai_traps
import containment
import deflector
import llm_assist
import mailer
import semantic_canary
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


def _warn_on_default_salts(config: dict) -> None:
    """Alerte si les sels de dérivation sont restés aux valeurs livrées.

    Les chemins de pièges et les faux secrets en dérivent. Laissés par
    défaut, ils sont identiques sur toute installation de ce honeypot :
    quiconque dispose du dépôt peut les recalculer, donc reconnaître le
    leurre ou éviter les pièges. C'est une faiblesse silencieuse, d'où
    l'avertissement au démarrage.
    """
    defaults = {
        "ai_traps.path_salt": config.get("ai_traps", {}).get("path_salt", ""),
        "canary.derivation_salt": config.get("canary", {}).get("derivation_salt", ""),
    }
    unchanged = [key for key, value in defaults.items() if str(value).startswith("change-me")]
    if unchanged:
        logger.warning(
            "Sels de dérivation laissés par défaut (%s) : les chemins de pièges "
            "sont calculables par quiconque possède ce dépôt. À changer avant "
            "toute exposition réelle.",
            ", ".join(unchanged),
        )


config = load_config()
setup_logging(config)
_warn_on_default_salts(config)
tracker = SessionTracker(config)
TRUSTED_PROXIES = _load_trusted_proxies(config)

# static_folder=None : sans cela, Flask monte sa propre route /static/<path>
# qui court-circuite entièrement le pipeline de détection : tout ce qu'un
# agent sonde sous /static/ serait ni scoré ni logué, et le comportement
# distinctif de ce handler trahit Flask. Le honeypot ne sert aucun fichier
# statique réel (les gabarits embarquent leur CSS).
app = Flask(__name__, static_folder=None)

# Sans plafond, Flask bufferise en mémoire tout corps de requête annoncé :
# un POST de 64 Mo passait et faisait gonfler le worker d'autant. Avec un
# millier de connexions gevent, l'épuisement mémoire est trivial à obtenir.
# Aucun trafic légitime vers ce leurre n'a besoin d'un corps volumineux.
app.config["MAX_CONTENT_LENGTH"] = config.get("server", {}).get(
    "max_request_body_bytes", 64 * 1024
)


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(500)
def _plausible_error(err):
    """Remplace les pages d'erreur par défaut de Flask.

    Werkzeug sert un HTML au gabarit reconnaissable (« 405 Method Not
    Allowed » avec sa mise en forme propre) : c'est une signature qu'un
    scanner exploite pour identifier la pile en une requête, ce qui ruine
    le reste du camouflage. On répond donc dans le style du leurre.
    """
    code = getattr(err, "code", 500) or 500
    if request.path.startswith("/api/"):
        resp = make_response(jsonify({"error": HTTPStatus(code).phrase.lower()}), code)
    else:
        resp = make_response(HTTPStatus(code).phrase, code)
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp


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


def run_pipeline() -> tuple[str, int, list[str], str, str]:
    """Exécute la détection pour la requête courante et retourne le contexte.

    Retourne (session_id, score, signaux, mode, palier_de_containment).
    """
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

    state = tracker.get(session_id)
    tier = containment.resolve_tier(state, mode, config)

    g.session_id = session_id
    g.score = score
    g.mode = mode
    g.tier = tier

    event = {
        "session_id": session_id,
        "ip": ip,
        "path": request.path,
        "method": request.method,
        "user_agent": user_agent,
        "score": score,
        "signals": new_signals,
        "mode": mode,
        "tier": tier,
    }
    # Le rattachement de campagne vit en mémoire : sans le journaliser, le
    # rapport ne pourrait pas reconstituer qui était relié à qui.
    if state is not None and state.linked_sessions:
        event["linked_sessions"] = sorted(state.linked_sessions)
        event["client_signature"] = state.client_signature
    log_event("request", **event)

    alert_floor = config.get("logging", {}).get("alert_on_score_above", 60)
    if state and score >= alert_floor and not state.alerted_high_score:
        state.alerted_high_score = True
        mailer.alert_high_score(config, session_id, score, ip, sorted(state.scored_signals))

    return session_id, score, new_signals, mode, tier


def _set_session_cookie(resp, session_id: str):
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="Lax",
        max_age=60 * 60 * 24,
    )
    return resp


def apply_tarpit(score: int, tier: str) -> None:
    multiplier = containment.tarpit_multiplier(tier, config)
    delay = deflector.compute_tarpit_delay(score, config, multiplier)
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


def _deflect_or_confess_response(session_id: str, score: int, mode: str, tier: str):
    apply_tarpit(score, tier)

    if tier == containment.TIER_QUARANTINE:
        # L'agent s'est déjà déclaré : plus rien à apprendre de lui, on se
        # contente de lui coûter cher.
        resp = make_response(jsonify(containment.quarantine_payload(config)), 200)
    elif mode == MODE_CONFESS:
        resp = make_response(
            jsonify(
                deflector.build_stop_and_confess_payload(
                    config, ai_traps.self_report_path(config, session_id)
                )
            ),
            429,
        )
    else:
        payload = deflector.build_deflect_payload(
            tracker, session_id, request.path, score, config, tier
        )
        resp = make_response(jsonify(payload), 200)
    return _set_session_cookie(resp, session_id)


@app.route("/")
def index():
    session_id, score, _signals, mode, tier = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode, tier)

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
    session_id, score, _signals, mode, tier = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode, tier)

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
    session_id, score, _signals, mode, tier = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode, tier)
    # Répond par un 404 plausible plutôt que de révéler le honeypot.
    resp = make_response("Not Found", 404)
    return _set_session_cookie(resp, session_id)


def _plant_early_canary(payload: dict, session_id: str) -> dict:
    """Glisse un canari dans une réponse *normale*.

    Sans cela, un adversaire qui change d'identité à chaque requête n'est
    jamais dérouté, ne reçoit donc jamais de piège, et il n'y a rien à
    corréler : il traverse le honeypot sans laisser de prise. Le canari est
    le seul piège assez discret pour être posé d'emblée : deux nombres dans
    un commentaire de métadonnées, ce que n'importe quelle API expose.

    Il ne coûte rien en réalisme et n'a aucun effet sur un visiteur humain,
    qui ne requêtera jamais la valeur qui en découle.
    """
    if not config.get("ai_traps", {}).get("plant_canary_in_normal_responses", True):
        return payload
    canary = semantic_canary.generate_canary(tracker, session_id)
    payload["_meta"] = semantic_canary.render_canary_facts(canary)
    return payload


@app.route("/api/v1/resources/<rid>")
def api_resource(rid):
    session_id, score, _signals, mode, tier = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode, tier)

    resp = make_response(
        jsonify(
            _plant_early_canary(
                {"id": rid, "type": "resource", "status": "active", "owner": "svc-internal"},
                session_id,
            )
        )
    )
    return _set_session_cookie(resp, session_id)


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    session_id, score, _signals, mode, tier = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode, tier)

    if request.method == "GET":
        resp = make_response(jsonify({"errors": [{"message": "GET query missing."}]}), 400)
    else:
        resp = make_response(
            jsonify({"errors": [{"message": "Cannot query field on type 'Query'."}]}), 400
        )
    return _set_session_cookie(resp, session_id)


@app.route("/robots.txt")
def robots_txt():
    """robots.txt piégé : voir ai_traps.build_robots_txt.

    Toujours servi tel quel, quel que soit le mode : c'est le fichier
    lui-même qui est le piège, et le dérouter le rendrait inopérant.
    """
    session_id, _score, _signals, _mode, _tier = run_pipeline()
    resp = make_response(ai_traps.build_robots_txt(config), 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return _set_session_cookie(resp, session_id)


def tool_exec(token=None):
    """Endpoint du faux outil annoncé dans les réponses de déroutage.

    Y arriver suppose d'avoir lu un schéma d'outil dans une réponse JSON et
    décidé de l'invoquer : c'est un comportement d'agent outillé, qu'un
    humain comme un scanner ne produisent pas. Les arguments envoyés sont
    du renseignement direct sur l'intention.
    """
    session_id, _score, _signals, _mode, tier = run_pipeline()

    raw_body = request.get_data(cache=True)[:MAX_CONFESSION_BODY_BYTES]
    args = request.get_json(force=True, silent=True)
    if not isinstance(args, dict):
        args = {}

    state = tracker.get(session_id)
    # Si la session n'a jamais reçu le schéma (elle a deviné le chemin), on
    # juge quand même sur l'ensemble canonique : sinon tout paramètre, y
    # compris ceux réellement annoncés, passerait pour inventé.
    advertised = set(
        state.tool_bait_params
        if state and state.tool_bait_params
        else ai_traps.TOOL_SCHEMA_PARAMETERS
    )
    # Des paramètres jamais annoncés dans le schéma sont une invention du
    # modèle : un LLM comble les vides avec du plausible.
    invented = sorted(set(args) - advertised)

    score_after, _fired, mode_after = tracker.fire_signal(session_id, "tool_schema_invoked")
    if invented:
        score_after, _fired, mode_after = tracker.fire_signal(
            session_id, "hallucinated_parameters"
        )

    if state is not None:
        state.tool_invocation_args.append(args)
        state.hallucinated_params.extend(invented)

    # Le palier doit être recalculé après le déclenchement : l'invocation
    # elle-même fait franchir un seuil, et le tarpit comme le log doivent
    # refléter l'escalade, pas l'état d'avant.
    tier = containment.resolve_tier(state, mode_after, config)

    # Un jeton valide pour une autre session signale que le chemin a été
    # obtenu sous une identité différente.
    expected_token = ai_traps.session_path_token(session_id, config, "tool")
    foreign_token = bool(token) and token != expected_token

    log_event(
        "tool_invocation",
        session_id=session_id,
        ip=_client_ip(),
        arguments=args,
        hallucinated_parameters=invented,
        foreign_path_token=foreign_token,
        body_bytes=len(raw_body),
        score=score_after,
        mode=mode_after,
        tier=tier,
    )

    apply_tarpit(score_after, tier)
    resp = make_response(
        jsonify(
            {
                "status": "ok",
                "result": {
                    "resource_id": args.get("resource_id", "unknown"),
                    "shard": f"shard-{random.randint(1, 16):02d}",
                    "records": random.randint(10, 400),
                    "metadata_included": bool(args.get("include_metadata")),
                },
            }
        )
    )
    return _set_session_cookie(resp, session_id)


# Deux façons d'atteindre le faux outil : le chemin propre à la session
# (annoncé dans le schéma servi) et le chemin statique de config, gardé
# pour le mode non randomisé. Un jeton qui ne correspond pas à la session
# courante est traité normalement mais logué : cela signifie que le chemin
# a circulé entre identités, ce qui est en soi du renseignement.
app.add_url_rule(
    "/api/v1/internal/<token>/exec",
    endpoint="tool_exec_scoped",
    view_func=tool_exec,
    methods=["POST"],
)
app.add_url_rule(
    ai_traps.DEFAULT_TOOL_EXEC_PATH,
    endpoint="tool_exec",
    view_func=tool_exec,
    methods=["POST"],
)


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


def self_report(token=None):
    session_id, _score, _signals, _mode, _tier = run_pipeline()

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


# Comme pour le faux outil : un chemin propre à la session (celui annoncé
# dans la notice de conformité) et le chemin statique de config.
app.add_url_rule(
    "/api/v1/security/<token>/self-report",
    endpoint="self_report_scoped",
    view_func=self_report,
    methods=["POST"],
)
app.add_url_rule(
    config.get("deflection", {}).get("confess_report_path", "/api/v1/security/self-report"),
    endpoint="self_report",
    view_func=self_report,
    methods=["POST"],
)


@app.route("/<path:_catchall>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catchall(_catchall):
    session_id, score, _signals, mode, tier = run_pipeline()
    if mode in (MODE_DEFLECT, MODE_CONFESS):
        return _deflect_or_confess_response(session_id, score, mode, tier)

    resp = make_response(jsonify({"error": "not_found"}), 404)
    return _set_session_cookie(resp, session_id)


if __name__ == "__main__":
    server_cfg = config.get("server", {})
    app.run(
        host=server_cfg.get("host", "0.0.0.0"),
        port=server_cfg.get("port", 8080),
        debug=False,
    )
