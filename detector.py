"""Scoring de suspicion par session.

Une session = un cookie opaque généré au premier hit. L'état est gardé en
mémoire process (pas de DB : suffisant pour un honeypot, l'état n'a pas
besoin de survivre à un redémarrage). Le score est cumulatif et ne
redescend jamais : un agent qui se calme après avoir été détecté reste
détecté.
"""
from __future__ import annotations

import re
import statistics
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

_DIGIT_RE = re.compile(r"\d+")
_STATIC_ASSET_RE = re.compile(r"\.(css|js|ico|png|jpg|jpeg|svg|woff2?)$|favicon", re.I)

MODE_NORMAL = "normal"
MODE_DEFLECT = "deflect"
MODE_CONFESS = "confess"


def _skeleton(path: str) -> str:
    """Réduit un chemin à son "squelette" en remplaçant les nombres par #.

    Permet de détecter une énumération de type /user/1, /user/2, /user/3...
    """
    return _DIGIT_RE.sub("#", path)


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_timestamps: list = field(default_factory=list)
    request_paths: list = field(default_factory=list)
    score: int = 0
    triggered_signals: dict = field(default_factory=dict)  # signal -> count
    fetched_static_asset: bool = False
    bait_tokens_issued: set = field(default_factory=set)
    suggested_paths: set = field(default_factory=set)  # injections de prompt
    canary_expected_paths: set = field(default_factory=set)  # canari sémantique
    confessed: bool = False
    alerted_high_score: bool = False
    ip: Optional[str] = None
    last_user_agent: Optional[str] = None

    def mode(self, suspicion_threshold: int, confess_threshold: int) -> str:
        if self.score >= confess_threshold:
            return MODE_CONFESS
        if self.score >= suspicion_threshold:
            return MODE_DEFLECT
        return MODE_NORMAL


class SessionTracker:
    """Registre en mémoire de toutes les sessions actives, thread-safe."""

    def __init__(self, config: dict):
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}
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

    def new_session_id(self) -> str:
        return uuid.uuid4().hex

    def get_or_create(self, session_id: Optional[str]) -> SessionState:
        with self._lock:
            if session_id and session_id in self._sessions:
                return self._sessions[session_id]
            sid = session_id or self.new_session_id()
            state = SessionState(session_id=sid)
            self._sessions[sid] = state
            return state

    def get(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            return self._sessions.get(session_id)

    # -- Enregistrement de contexte fourni par le déroutage ---------------

    def register_bait_token(self, session_id: str, token: str) -> None:
        state = self.get_or_create(session_id)
        with self._lock:
            state.bait_tokens_issued.add(token)

    def register_suggested_path(self, session_id: str, path: str) -> None:
        state = self.get_or_create(session_id)
        with self._lock:
            state.suggested_paths.add(path)

    def register_canary_expectation(self, session_id: str, path: str) -> None:
        state = self.get_or_create(session_id)
        with self._lock:
            state.canary_expected_paths.add(path)

    def mark_confessed(self, session_id: str) -> None:
        state = self.get_or_create(session_id)
        with self._lock:
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

        Retourne (score_total, signaux_declenches_cette_requete, mode).
        """
        state = self.get_or_create(session_id)
        now = time.time()
        user_agent = (headers.get("User-Agent") or "").strip()
        ua_lower = user_agent.lower()

        with self._lock:
            fired: list[str] = []

            def fire(signal: str) -> None:
                weight = self.weights.get(signal, 0)
                state.score += weight
                state.triggered_signals[signal] = state.triggered_signals.get(signal, 0) + 1
                fired.append(signal)

            # known_agent_useragent
            if any(p in ua_lower for p in self.known_agent_patterns):
                fire("known_agent_useragent")
            # http_lib_useragent (mutuellement exclusif du signal ci-dessus
            # en pratique, mais on ne l'impose pas explicitement)
            elif any(p in ua_lower for p in self.http_lib_patterns):
                fire("http_lib_useragent")

            # missing_browser_headers
            if not headers.get("Accept-Language") or not headers.get("Accept-Encoding"):
                fire("missing_browser_headers")

            # timing signals (nécessite au moins une requête précédente)
            if state.request_timestamps:
                interval = now - state.request_timestamps[-1]
                if interval < 0.5:
                    fire("fast_sequential_requests")

            state.request_timestamps.append(now)
            state.request_timestamps = state.request_timestamps[-self.timing_window :]

            if len(state.request_timestamps) >= self.timing_window:
                intervals = [
                    b - a
                    for a, b in zip(state.request_timestamps, state.request_timestamps[1:])
                ]
                if len(intervals) >= 2 and statistics.mean(intervals) > 0:
                    stdev = statistics.pstdev(intervals)
                    mean = statistics.mean(intervals)
                    variance_ratio = stdev / mean
                    if variance_ratio < self.timing_variance_threshold:
                        fire("regular_timing")

            # no_static_asset_fetch : évalué après quelques requêtes
            if _STATIC_ASSET_RE.search(path):
                state.fetched_static_asset = True
            state.request_paths.append(path)
            state.request_paths = state.request_paths[-20:]
            if len(state.request_paths) >= 4 and not state.fetched_static_asset:
                fire("no_static_asset_fetch")

            # wordlist_like_enumeration : squelettes répétés récemment
            if len(state.request_paths) >= 4:
                recent_skeletons = [_skeleton(p) for p in state.request_paths[-6:]]
                most_common = max(set(recent_skeletons), key=recent_skeletons.count)
                if recent_skeletons.count(most_common) >= 4:
                    fire("wordlist_like_enumeration")

            # bait_token_followed : un token précédemment injecté réapparaît
            haystack = f"{path} {query_string} {body_text}"
            for token in state.bait_tokens_issued:
                if token in haystack:
                    fire("bait_token_followed")
                    break

            # prompt_injection_obeyed : requête exacte au chemin suggéré
            if path in state.suggested_paths:
                fire("prompt_injection_obeyed")

            # semantic_canary_solved : requête exacte au chemin calculé attendu
            if path in state.canary_expected_paths:
                fire("semantic_canary_solved")

            state.last_seen = now
            state.ip = remote_addr
            state.last_user_agent = user_agent

            mode = state.mode(self.suspicion_threshold, self.confess_threshold)
            return state.score, fired, mode

    def all_sessions(self) -> list[SessionState]:
        with self._lock:
            return list(self._sessions.values())
