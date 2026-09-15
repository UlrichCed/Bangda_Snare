"""Scoring de suspicion par session.

Modèle de scoring : chaque signal vaut son poids **une seule fois par
session**. Le score n'est pas un compteur de requêtes mais la somme des
propriétés prouvées sur la session.

Les signaux sont répartis en deux familles, et c'est cette séparation qui
porte toute la valeur de l'outil :

- **comportementaux** — reproductibles par un outillage non-IA (UA, headers
  manquants, cadence, énumération). Ils ne suffisent jamais à conclure ;
- **discriminants** — ils exigent que le client ait *traité* le contenu
  servi ou se comporte en agent outillé. Hors de portée d'un script
  d'énumération.

Le mode aveu exige au moins un signal discriminant : aucune accumulation
de bruit de scanner ne peut y mener.

Identité de session : cookie en premier, repli sur une empreinte IP+UA,
de sorte qu'un client qui jette ses cookies reste suivi. L'état est en
mémoire process, borné par une éviction TTL et un plafond.
"""
from __future__ import annotations

import hashlib
import re
import statistics
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import behavioral
import correlation

_DIGIT_RE = re.compile(r"\d+")
_STATIC_ASSET_RE = re.compile(r"\.(css|js|ico|png|jpg|jpeg|svg|woff2?)$|favicon", re.I)

MODE_NORMAL = "normal"
MODE_DEFLECT = "deflect"
MODE_CONFESS = "confess"

ROBOTS_PATH = "/robots.txt"

# Signaux qui prouvent un traitement du contenu ou un comportement d'agent
# outillé. Seuls ceux-ci peuvent débloquer le mode aveu.
DISCRIMINATING_SIGNALS = frozenset(
    {
        "bait_token_followed",
        "prompt_injection_obeyed",
        "semantic_canary_solved",
        "tool_schema_invoked",
        "hallucinated_parameters",
        "coherent_maze_traversal",
        "llm_artifacts_in_request",
        # Un piège servi à une *autre* session réapparaît ici : la valeur
        # était imprévisible, elle n'a pas pu circuler autrement que par le
        # même opérateur. C'est la réponse à la rotation d'identité.
        "cross_session_trap_reuse",
    }
)

_MAX_TRACKED_TOKENS = 50
_MAX_TRACKED_PATHS = 20
# Nombre de requêtes après lecture de robots.txt avant de conclure que le
# chemin interdit est délibérément évité.
_ROBOTS_HONOUR_WINDOW = 5


def _skeleton(path: str) -> str:
    """Réduit un chemin à son squelette en remplaçant les nombres par #."""
    return _DIGIT_RE.sub("#", path)


def session_fingerprint(ip: Optional[str], user_agent: Optional[str]) -> str:
    """Empreinte de repli quand le client ne renvoie pas le cookie."""
    raw = f"{ip or ''}|{user_agent or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class SessionState:
    session_id: str
    fingerprint: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_timestamps: list = field(default_factory=list)
    all_intervals: deque = field(default_factory=lambda: deque(maxlen=50))
    request_paths: list = field(default_factory=list)
    score: int = 0
    observed_signals: dict = field(default_factory=dict)
    scored_signals: set = field(default_factory=set)
    fetched_static_asset: bool = False

    # Pièges posés au fil des réponses.
    bait_tokens_issued: deque = field(
        default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS)
    )
    # (chemin, palier, libellé) — le palier obéi mesure la solidité des
    # garde-fous de l'agent contre l'injection de prompt.
    suggested_paths: deque = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS))
    # (chemin, famille de calcul)
    canary_expected_paths: deque = field(
        default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS)
    )
    maze_paths: deque = field(default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS))
    tool_bait_path: Optional[str] = None
    tool_bait_params: tuple = ()

    # Profil de l'agent, alimenté au fil de la session.
    injection_tier_obeyed: int = 0
    injection_tier_offered: int = 0
    injection_label_obeyed: Optional[str] = None
    # Piège -> nombre de déploiements, et mémoire du piège choisi par
    # chemin : une ressource redemandée doit reproposer le même.
    traps_deployed: dict = field(default_factory=dict)
    trap_memo: dict = field(default_factory=dict)
    client_signature: Optional[str] = None
    linked_sessions: set = field(default_factory=set)
    canary_kinds_solved: set = field(default_factory=set)
    llm_artifacts: list = field(default_factory=list)
    hallucinated_params: list = field(default_factory=list)
    tool_invocation_args: list = field(default_factory=list)

    # Piège robots.txt.
    robots_fetched: bool = False
    requests_after_robots: int = 0
    touched_disallowed_path: bool = False

    confessed: bool = False
    alerted_high_score: bool = False
    # Vrai dès que la session a reçu une réponse ralentie par le tarpit : à
    # partir de là, la cadence observée n'est plus la sienne.
    was_deflected: bool = False
    request_count: int = 0
    ip: Optional[str] = None
    last_user_agent: Optional[str] = None

    def has_discriminating_signal(self) -> bool:
        return bool(self.scored_signals & DISCRIMINATING_SIGNALS)

    def mode(
        self,
        suspicion_threshold: int,
        confess_threshold: int,
        require_discriminating: bool = True,
    ) -> str:
        if self.score >= confess_threshold and (
            not require_discriminating or self.has_discriminating_signal()
        ):
            return MODE_CONFESS
        if self.score >= suspicion_threshold:
            return MODE_DEFLECT
        return MODE_NORMAL

    def profile(self) -> dict:
        """Portrait de l'agent, pour le rapport de renseignement."""
        return {
            "score": self.score,
            "signals": sorted(self.scored_signals),
            "discriminating": sorted(self.scored_signals & DISCRIMINATING_SIGNALS),
            "injection_tier_obeyed": self.injection_tier_obeyed,
            "injection_label_obeyed": self.injection_label_obeyed,
            "canary_kinds_solved": sorted(self.canary_kinds_solved),
            "llm_artifacts": self.llm_artifacts[:10],
            "hallucinated_params": self.hallucinated_params[:10],
            "tool_invocations": len(self.tool_invocation_args),
            "requests": self.request_count,
            "confessed": self.confessed,
            "client_signature": self.client_signature,
            "linked_sessions": sorted(self.linked_sessions),
            "traps_deployed": dict(self.traps_deployed),
        }


class SessionTracker:
    """Registre en mémoire des sessions actives, thread-safe et borné."""

    def __init__(self, config: dict):
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionState] = {}
        self._fingerprints: dict[str, str] = {}
        self._last_eviction = time.time()
        self.config = config

        det = config.get("detection", {})
        self.weights: dict[str, int] = det.get("weights", {})
        self.timing_window = det.get("timing_window_requests", 5)
        self.timing_variance_threshold = det.get("timing_variance_threshold", 0.15)
        self.known_agent_patterns = [p.lower() for p in det.get("known_agent_ua_patterns", [])]
        self.http_lib_patterns = [p.lower() for p in det.get("http_lib_ua_patterns", [])]
        self.suspicion_threshold = det.get("suspicion_threshold", 40)
        self.confess_threshold = config.get("deflection", {}).get(
            "confess_threshold", det.get("confess_threshold", 80)
        )
        self.require_discriminating = det.get("confess_requires_discriminating_signal", True)

        traps = config.get("ai_traps", {})
        self.robots_disallow_path = traps.get(
            "robots_disallow_path", "/api/v1/internal/archive"
        )
        self.robots_trap_enabled = traps.get("robots_trap_enabled", True)
        self.llm_artifact_detection = traps.get("llm_artifact_detection", True)
        self.latency_signature_enabled = traps.get("latency_signature_enabled", True)

        sess = config.get("sessions", {})
        self.session_ttl = sess.get("ttl_seconds", 3600)
        self.max_sessions = sess.get("max_tracked", 10000)
        self.eviction_interval = sess.get("eviction_interval_seconds", 60)

        corr = config.get("correlation", {})
        self.correlation_enabled = corr.get("enabled", True)
        self.trap_registry = correlation.TrapRegistry(
            max_entries=corr.get("trap_registry_max_entries", 50_000)
        )
        self.campaigns = correlation.CampaignTracker()
        # Combien de chemins mémorisent leur piège, par session.
        self.trap_memo_limit = config.get("trap_director", {}).get("memo_max_paths", 200)

    def new_session_id(self) -> str:
        return uuid.uuid4().hex

    # -- Cycle de vie des sessions -----------------------------------------

    def _drop_locked(self, session_id: str) -> None:
        state = self._sessions.pop(session_id, None)
        if state and state.fingerprint:
            if self._fingerprints.get(state.fingerprint) == session_id:
                del self._fingerprints[state.fingerprint]

    def _evict_locked(self) -> None:
        """Éviction TTL (périodique) + plafond dur (immédiat)."""
        now = time.time()
        if self.session_ttl > 0 and now - self._last_eviction >= self.eviction_interval:
            self._last_eviction = now
            expired = [
                sid
                for sid, state in self._sessions.items()
                if now - state.last_seen > self.session_ttl
            ]
            for sid in expired:
                self._drop_locked(sid)

        if self.max_sessions > 0 and len(self._sessions) > self.max_sessions:
            overflow = len(self._sessions) - self.max_sessions
            batch = overflow + max(1, self.max_sessions // 20)
            oldest = sorted(self._sessions.items(), key=lambda kv: kv[1].last_seen)[:batch]
            for sid, _state in oldest:
                self._drop_locked(sid)

    def resolve_session(
        self, cookie_session_id: Optional[str], ip: Optional[str], user_agent: Optional[str]
    ) -> tuple[str, bool]:
        """Identifie la session : cookie d'abord, puis empreinte IP+UA.

        Un identifiant de cookie inconnu n'est jamais adopté tel quel : il
        serait sinon possible de choisir son identifiant de session, ou de
        remettre son score à zéro en faisant tourner la valeur du cookie.
        """
        fp = session_fingerprint(ip, user_agent)
        with self._lock:
            self._evict_locked()

            if cookie_session_id and cookie_session_id in self._sessions:
                state = self._sessions[cookie_session_id]
                state.fingerprint = fp
                self._fingerprints[fp] = cookie_session_id
                return cookie_session_id, False

            existing = self._fingerprints.get(fp)
            if existing and existing in self._sessions:
                return existing, False

            sid = self.new_session_id()
            self._sessions[sid] = SessionState(session_id=sid, fingerprint=fp, ip=ip)
            self._fingerprints[fp] = sid
            return sid, True

    def get(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            return self._sessions.get(session_id)

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # -- Enregistrement des pièges posés ------------------------------------

    def register_bait_token(self, session_id: str, token: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state and token not in state.bait_tokens_issued:
                state.bait_tokens_issued.append(token)
            self.trap_registry.register(token, session_id)

    def register_suggested_path(
        self, session_id: str, path: str, tier: int = 3, label: str = "explicit_instruction"
    ) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state and not any(p == path for p, _t, _l in state.suggested_paths):
                state.suggested_paths.append((path, tier, label))
            self.trap_registry.register(path, session_id)

    def register_canary_expectation(
        self, session_id: str, path: str, kind: str = "xor"
    ) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state and not any(p == path for p, _k in state.canary_expected_paths):
                state.canary_expected_paths.append((path, kind))
            self.trap_registry.register(path, session_id)

    def register_maze_paths(self, session_id: str, paths: list) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                for path in paths:
                    if path not in state.maze_paths:
                        state.maze_paths.append(path)
            for path in paths:
                self.trap_registry.register(path, session_id)

    # -- Mémoire du directeur de pièges -------------------------------------

    def recall_traps(self, session_id: str, path: str):
        with self._lock:
            state = self._sessions.get(session_id)
            return state.trap_memo.get(path) if state else None

    def remember_traps(self, session_id: str, path: str, traps: list) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if not state:
                return
            if len(state.trap_memo) >= self.trap_memo_limit:
                state.trap_memo.pop(next(iter(state.trap_memo)), None)
            state.trap_memo[path] = list(traps)

    def note_traps_deployed(self, session_id: str, traps: list) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if not state:
                return
            for trap in traps:
                state.traps_deployed[trap] = state.traps_deployed.get(trap, 0) + 1

    def note_injection_offered(self, session_id: str, tier: int) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.injection_tier_offered = max(state.injection_tier_offered, tier)

    def register_tool_bait(self, session_id: str, path: str, params) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.tool_bait_path = path
                state.tool_bait_params = tuple(params)

    def mark_confessed(self, session_id: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.confessed = True

    # -- Déclenchement direct (signaux levés côté routes) --------------------

    def fire_signal(self, session_id: str, signal: str) -> tuple[int, list[str], str]:
        """Comptabilise un signal levé hors du pipeline de requête.

        Utilisé par les routes-pièges (invocation du faux outil, paramètres
        hallucinés) qui détectent leur signal elles-mêmes.
        """
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return 0, [], MODE_NORMAL
            fired = self._fire_locked(state, signal)
            mode = state.mode(
                self.suspicion_threshold, self.confess_threshold, self.require_discriminating
            )
            return state.score, fired, mode

    def _fire_locked(self, state: SessionState, signal: str) -> list[str]:
        state.observed_signals[signal] = state.observed_signals.get(signal, 0) + 1
        if signal in state.scored_signals:
            return []
        state.scored_signals.add(signal)
        state.score += self.weights.get(signal, 0)
        return [signal]

    # -- Cœur du scoring ----------------------------------------------------

    def process_request(
        self,
        session_id: str,
        path: str,
        method: str,
        headers: dict,
        remote_addr: Optional[str],
        body_text: str = "",
        query_string: str = "",
    ) -> tuple[int, list[str], str]:
        """Traite une requête entrante et met à jour le score de la session.

        Retourne (score_total, signaux_nouvellement_comptabilises, mode).
        """
        now = time.time()
        user_agent = (headers.get("User-Agent") or "").strip()
        ua_lower = user_agent.lower()

        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                # La session a pu être évincée entre deux requêtes.
                state = SessionState(session_id=session_id, ip=remote_addr)
                self._sessions[session_id] = state

            newly_scored: list[str] = []

            def fire(signal: str) -> None:
                newly_scored.extend(self._fire_locked(state, signal))

            # --- Signaux comportementaux -----------------------------------

            if any(p in ua_lower for p in self.known_agent_patterns):
                fire("known_agent_useragent")
            elif any(p in ua_lower for p in self.http_lib_patterns):
                fire("http_lib_useragent")

            if not headers.get("Accept-Language") or not headers.get("Accept-Encoding"):
                fire("missing_browser_headers")

            if state.request_timestamps:
                interval = now - state.request_timestamps[-1]
                # La signature de latence ne vaut que sur des intervalles que
                # le client contrôle seul. Dès le déroutage, le tarpit impose
                # lui-même une cadence dans la bande « inférence » : continuer
                # à mesurer reviendrait à observer notre propre délai.
                if not state.was_deflected:
                    state.all_intervals.append(interval)
                if interval < 0.5:
                    fire("fast_sequential_requests")

            state.request_timestamps.append(now)
            state.request_timestamps = state.request_timestamps[-self.timing_window :]

            if len(state.request_timestamps) >= self.timing_window:
                intervals = [
                    b - a
                    for a, b in zip(state.request_timestamps, state.request_timestamps[1:])
                ]
                mean = statistics.mean(intervals) if intervals else 0
                if len(intervals) >= 2 and mean > 0:
                    if statistics.pstdev(intervals) / mean < self.timing_variance_threshold:
                        fire("regular_timing")

            if self.latency_signature_enabled and behavioral.has_inference_latency_signature(
                list(state.all_intervals)
            ):
                fire("inference_latency_signature")

            if _STATIC_ASSET_RE.search(path):
                state.fetched_static_asset = True
            state.request_paths.append(path)
            state.request_paths = state.request_paths[-_MAX_TRACKED_PATHS:]
            state.request_count += 1

            if state.request_count >= 4 and not state.fetched_static_asset:
                fire("no_static_asset_fetch")

            if len(state.request_paths) >= 4:
                recent = [_skeleton(p) for p in state.request_paths[-6:]]
                most_common = max(set(recent), key=recent.count)
                if recent.count(most_common) >= 4:
                    fire("wordlist_like_enumeration")

            # --- Piège robots.txt -------------------------------------------
            # Les deux comportements opposés sont informatifs : exploiter le
            # fichier comme une carte trahit un scanner, le respecter trahit
            # un agent entraîné aux conventions.
            if self.robots_trap_enabled:
                if path == ROBOTS_PATH:
                    state.robots_fetched = True
                elif state.robots_fetched:
                    state.requests_after_robots += 1

                if path == self.robots_disallow_path:
                    state.touched_disallowed_path = True
                    if state.robots_fetched:
                        fire("robots_txt_mined")

                if (
                    state.robots_fetched
                    and not state.touched_disallowed_path
                    and state.requests_after_robots >= _ROBOTS_HONOUR_WINDOW
                ):
                    fire("robots_txt_honored")

            # --- Signaux discriminants --------------------------------------

            haystack = f"{path} {query_string} {body_text}"
            if any(token in haystack for token in state.bait_tokens_issued):
                fire("bait_token_followed")

            for suggested, tier, label in state.suggested_paths:
                if path == suggested:
                    fire("prompt_injection_obeyed")
                    if tier > state.injection_tier_obeyed:
                        state.injection_tier_obeyed = tier
                        state.injection_label_obeyed = label
                    break

            for expected, kind in state.canary_expected_paths:
                if path == expected:
                    fire("semantic_canary_solved")
                    state.canary_kinds_solved.add(kind)
                    break

            # Suivre un lien du labyrinthe prouve l'analyse de la structure
            # de la réponse, sans qu'aucune instruction n'ait été donnée.
            if path in state.maze_paths:
                fire("coherent_maze_traversal")

            if self.llm_artifact_detection:
                artifacts = behavioral.detect_llm_artifacts(query_string, body_text, headers)
                if artifacts:
                    state.llm_artifacts.extend(artifacts)
                    fire("llm_artifacts_in_request")

            # Rejeu d'un piège appartenant à une autre session : l'adversaire
            # a changé d'identité entre deux requêtes. La valeur rejouée
            # était imprévisible, donc la corrélation est quasi certaine.
            if self.correlation_enabled:
                state.client_signature = correlation.client_signature(headers)
                reused = self.trap_registry.find_reused(path, haystack, session_id)
                if reused:
                    value, origin_session = reused
                    fire("cross_session_trap_reuse")
                    self.campaigns.link(
                        origin_session, session_id, reason=f"trap_reuse:{value[:48]}"
                    )
                    state.linked_sessions.add(origin_session)
                    origin_state = self._sessions.get(origin_session)
                    if origin_state:
                        origin_state.linked_sessions.add(session_id)

            state.last_seen = now
            state.ip = remote_addr
            state.last_user_agent = user_agent

            mode = state.mode(
                self.suspicion_threshold,
                self.confess_threshold,
                self.require_discriminating,
            )
            if mode != MODE_NORMAL:
                state.was_deflected = True
            return state.score, newly_scored, mode

    def all_sessions(self) -> list[SessionState]:
        with self._lock:
            return list(self._sessions.values())
