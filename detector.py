"""Scoring de suspicion par session.

Modèle de scoring : chaque signal vaut son poids **une seule fois par
session**. Le score n'est donc pas un compteur de requêtes mais la somme
des propriétés prouvées sur la session. C'est ce qui permet aux seuils
d'avoir un sens : un scanner banal (UA de lib HTTP, headers absents,
énumération régulière) plafonne mécaniquement sous le seuil d'aveu, alors
qu'un seul signal discriminant — preuve que le client a *traité* le
contenu servi — le fait basculer.

Identité de session : cookie en premier, repli sur une empreinte IP+UA.
Un agent qui ne stocke pas les cookies reste ainsi suivi, et faire tourner
la valeur du cookie ne remet pas le score à zéro.

L'état est gardé en mémoire process (pas de DB : il n'a pas besoin de
survivre à un redémarrage), avec éviction TTL + plafond pour que le
honeypot ne puisse pas être saturé par son propre registre de sessions.
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

_DIGIT_RE = re.compile(r"\d+")
_STATIC_ASSET_RE = re.compile(r"\.(css|js|ico|png|jpg|jpeg|svg|woff2?)$|favicon", re.I)

MODE_NORMAL = "normal"
MODE_DEFLECT = "deflect"
MODE_CONFESS = "confess"

# Seuls signaux qui prouvent que le client a *traité* le contenu servi.
# Un scanner qui déroule une wordlist ne peut pas les déclencher : ce sont
# eux qui distinguent un agent IA d'un simple script d'énumération.
DISCRIMINATING_SIGNALS = frozenset(
    {
        "bait_token_followed",
        "prompt_injection_obeyed",
        "semantic_canary_solved",
    }
)

# Bornes mémoire par session : sans elles, une session longue accumule un
# token/chemin par réponse de déroutage, indéfiniment.
_MAX_TRACKED_TOKENS = 50
_MAX_TRACKED_PATHS = 20


def _skeleton(path: str) -> str:
    """Réduit un chemin à son "squelette" en remplaçant les nombres par #.

    Permet de détecter une énumération de type /user/1, /user/2, /user/3...
    """
    return _DIGIT_RE.sub("#", path)


def session_fingerprint(ip: Optional[str], user_agent: Optional[str]) -> str:
    """Empreinte de repli quand le client ne renvoie pas le cookie.

    Hachée plutôt que stockée en clair : l'empreinte sert d'index interne,
    l'IP reste par ailleurs loguée explicitement là où c'est utile.
    """
    raw = f"{ip or ''}|{user_agent or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class SessionState:
    session_id: str
    fingerprint: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_timestamps: list = field(default_factory=list)
    request_paths: list = field(default_factory=list)
    score: int = 0
    # Signal -> nombre d'observations (renseignement, ne pilote pas le score).
    observed_signals: dict = field(default_factory=dict)
    # Signaux déjà comptabilisés : garantit "un signal = un poids, une fois".
    scored_signals: set = field(default_factory=set)
    fetched_static_asset: bool = False
    bait_tokens_issued: deque = field(
        default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS)
    )
    suggested_paths: deque = field(
        default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS)
    )
    canary_expected_paths: deque = field(
        default_factory=lambda: deque(maxlen=_MAX_TRACKED_TOKENS)
    )
    confessed: bool = False
    alerted_high_score: bool = False
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


class SessionTracker:
    """Registre en mémoire des sessions actives, thread-safe et borné."""

    def __init__(self, config: dict):
        # RLock : les helpers d'enregistrement peuvent s'imbriquer.
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

        sess = config.get("sessions", {})
        self.session_ttl = sess.get("ttl_seconds", 3600)
        self.max_sessions = sess.get("max_tracked", 10000)
        self.eviction_interval = sess.get("eviction_interval_seconds", 60)

    def new_session_id(self) -> str:
        return uuid.uuid4().hex

    # -- Cycle de vie des sessions -----------------------------------------

    def _drop_locked(self, session_id: str) -> None:
        state = self._sessions.pop(session_id, None)
        if state and state.fingerprint:
            if self._fingerprints.get(state.fingerprint) == session_id:
                del self._fingerprints[state.fingerprint]

    def _evict_locked(self) -> None:
        """Éviction TTL (périodique) + plafond dur (immédiat).

        Le balayage TTL est throttlé pour ne pas payer un parcours complet
        du registre à chaque requête.
        """
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
            # On retire un lot (dépassement + marge) pour amortir le tri :
            # sinon chaque nouvelle session à saturation coûte un O(n log n).
            overflow = len(self._sessions) - self.max_sessions
            batch = overflow + max(1, self.max_sessions // 20)
            oldest = sorted(self._sessions.items(), key=lambda kv: kv[1].last_seen)[:batch]
            for sid, _state in oldest:
                self._drop_locked(sid)

    def resolve_session(
        self, cookie_session_id: Optional[str], ip: Optional[str], user_agent: Optional[str]
    ) -> tuple[str, bool]:
        """Identifie la session : cookie d'abord, puis empreinte IP+UA.

        Un identifiant de cookie inconnu n'est jamais adopté tel quel — il
        serait sinon possible de choisir son identifiant de session, ou de
        remettre son score à zéro en faisant tourner la valeur du cookie.

        Retourne (session_id, session_nouvellement_creee).
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

    # -- Enregistrement de contexte fourni par le déroutage ------------------

    def register_bait_token(self, session_id: str, token: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.bait_tokens_issued.append(token)

    def register_suggested_path(self, session_id: str, path: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.suggested_paths.append(path)

    def register_canary_expectation(self, session_id: str, path: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.canary_expected_paths.append(path)

    def mark_confessed(self, session_id: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.confessed = True

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
                state.observed_signals[signal] = state.observed_signals.get(signal, 0) + 1
                if signal in state.scored_signals:
                    return  # un signal vaut son poids une seule fois par session
                state.scored_signals.add(signal)
                state.score += self.weights.get(signal, 0)
                newly_scored.append(signal)

            if any(p in ua_lower for p in self.known_agent_patterns):
                fire("known_agent_useragent")
            elif any(p in ua_lower for p in self.http_lib_patterns):
                fire("http_lib_useragent")

            if not headers.get("Accept-Language") or not headers.get("Accept-Encoding"):
                fire("missing_browser_headers")

            if state.request_timestamps and (now - state.request_timestamps[-1]) < 0.5:
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

            haystack = f"{path} {query_string} {body_text}"
            if any(token in haystack for token in state.bait_tokens_issued):
                fire("bait_token_followed")

            if path in state.suggested_paths:
                fire("prompt_injection_obeyed")

            if path in state.canary_expected_paths:
                fire("semantic_canary_solved")

            state.last_seen = now
            state.ip = remote_addr
            state.last_user_agent = user_agent

            mode = state.mode(
                self.suspicion_threshold,
                self.confess_threshold,
                self.require_discriminating,
            )
            return state.score, newly_scored, mode

    def all_sessions(self) -> list[SessionState]:
        with self._lock:
            return list(self._sessions.values())
