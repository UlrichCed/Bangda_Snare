"""Corrélation de campagne : suivre un adversaire qui change d'identité.

Une attaque menée par agent tourne rarement depuis une seule identité :
proxies tournants, user-agent régénéré, cookies jetés. Le scoring par
session, à lui seul, n'y résiste pas : chaque requête repart de zéro et
aucun seuil n'est jamais atteint.

Deux mécanismes répondent à ça, d'une solidité très différente.

**Rejeu de piège entre sessions (preuve).** Chaque piège posé : chemin de
canari, token appât, chemin d'injection : est une valeur imprévisible
tirée dans un espace immense, servie à *une* session. Si elle réapparaît
dans une requête venue d'une autre session, il n'existe qu'une
explication : le même opérateur est derrière les deux. L'information n'a
pas pu circuler autrement. C'est une corrélation quasi certaine, et
précisément ce qui rattrape l'agent qui lit une réponse sous une identité
puis enchaîne sous une autre.

**Signature de client (indice).** L'ensemble et l'ordre des en-têtes
survivent à une rotation d'IP et d'UA, et sont caractéristiques d'une
bibliothèque ou d'un framework. Bien plus faible : de nombreux clients
légitimes partagent la même signature. Elle sert donc à regrouper pour
l'analyse, jamais à conclure.
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections import OrderedDict
from typing import Optional

# Formes que peut prendre un piège rejoué dans une requête : un chemin
# d'API, ou un token opaque suffisamment long pour ne pas être fortuit.
_CANDIDATE_RE = re.compile(r"/api/v\d+/[\w./-]+|[A-Za-z0-9_-]{12,80}")
_MAX_CANDIDATES = 40

# En-têtes dont la valeur est trop variable ou trop identifiante pour
# entrer dans une signature censée survivre à une rotation d'identité.
_VOLATILE_HEADERS = frozenset(
    {
        "user-agent",
        "cookie",
        "host",
        "content-length",
        "authorization",
        "referer",
        "x-forwarded-for",
        "x-real-ip",
        "date",
        "if-none-match",
        "if-modified-since",
    }
)

# Valeurs d'en-têtes assez structurantes pour distinguer des outillages.
_SIGNATURE_VALUE_HEADERS = ("accept", "accept-encoding", "accept-language", "connection")


def client_signature(headers: dict) -> str:
    """Signature d'outillage, indépendante de l'IP et du user-agent.

    Repose sur l'ensemble *et l'ordre* des en-têtes envoyés, plus la valeur
    de quelques en-têtes structurants. Deux sessions d'un même agent la
    partagent même après rotation complète d'identité, mais des clients
    légitimes sans rapport aussi, d'où son statut d'indice.
    """
    names = [name.lower() for name in headers.keys() if name.lower() not in _VOLATILE_HEADERS]
    values = [
        f"{name}={str(headers.get(name, '') or headers.get(name.title(), ''))[:120]}"
        for name in _SIGNATURE_VALUE_HEADERS
    ]
    raw = "|".join(names) + "||" + "|".join(values)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


class TrapRegistry:
    """Registre global des pièges posés, toutes sessions confondues.

    Borné en taille : un honeypot ne doit pas pouvoir être gonflé par son
    propre registre. Les entrées les plus anciennes sont évincées.
    """

    def __init__(self, max_entries: int = 50_000):
        self._lock = threading.Lock()
        self._owners: OrderedDict[str, str] = OrderedDict()
        self.max_entries = max_entries

    def register(self, value: str, session_id: str) -> None:
        if not value:
            return
        with self._lock:
            if value in self._owners:
                self._owners.move_to_end(value)
                return
            self._owners[value] = session_id
            while len(self._owners) > self.max_entries:
                self._owners.popitem(last=False)

    def owner(self, value: str) -> Optional[str]:
        with self._lock:
            return self._owners.get(value)

    def find_reused(
        self, path: str, haystack: str, session_id: str
    ) -> Optional[tuple[str, str]]:
        """Cherche un piège d'une *autre* session réapparaissant dans la requête.

        Retourne (valeur, session_emettrice) ou None.

        On extrait d'abord les candidats plausibles de la requête, puis on
        les cherche par clé. Balayer tout le registre à chaque requête
        coûterait un parcours de dizaines de milliers d'entrées : le
        honeypot s'effondrerait sous sa propre défense.
        """
        candidates = [path]
        candidates.extend(_CANDIDATE_RE.findall(haystack)[:_MAX_CANDIDATES])

        with self._lock:
            for candidate in candidates:
                owner = self._owners.get(candidate)
                if owner and owner != session_id:
                    return candidate, owner
        return None

    def size(self) -> int:
        with self._lock:
            return len(self._owners)


class CampaignTracker:
    """Regroupe en campagnes les sessions reliées entre elles.

    Union-find : relier A à B puis B à C place les trois dans la même
    campagne, sans qu'aucune passe de consolidation ne soit nécessaire.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._parent: dict[str, str] = {}
        self._evidence: dict[str, set] = {}

    def _find_locked(self, session_id: str) -> str:
        parent = self._parent.setdefault(session_id, session_id)
        while parent != self._parent[parent]:
            # Compression de chemin : garde les recherches quasi constantes.
            self._parent[parent] = self._parent[self._parent[parent]]
            parent = self._parent[parent]
        return parent

    def link(self, session_a: str, session_b: str, reason: str = "") -> str:
        """Relie deux sessions et retourne l'identifiant de la campagne."""
        with self._lock:
            root_a = self._find_locked(session_a)
            root_b = self._find_locked(session_b)
            if root_a != root_b:
                self._parent[root_b] = root_a
                merged = self._evidence.pop(root_b, set())
                self._evidence.setdefault(root_a, set()).update(merged)
            if reason:
                self._evidence.setdefault(root_a, set()).add(reason)
            return root_a

    def campaign_of(self, session_id: str) -> Optional[str]:
        with self._lock:
            if session_id not in self._parent:
                return None
            return self._find_locked(session_id)

    def members(self, session_id: str) -> set:
        with self._lock:
            root = self._find_locked(session_id)
            return {sid for sid in self._parent if self._find_locked(sid) == root}

    def evidence(self, session_id: str) -> set:
        with self._lock:
            return set(self._evidence.get(self._find_locked(session_id), set()))

    def campaigns(self) -> dict:
        """Campagnes comptant plus d'une session, avec leurs preuves."""
        with self._lock:
            grouped: dict[str, set] = {}
            for sid in self._parent:
                grouped.setdefault(self._find_locked(sid), set()).add(sid)
            return {
                root: {"sessions": members, "evidence": set(self._evidence.get(root, set()))}
                for root, members in grouped.items()
                if len(members) > 1
            }
