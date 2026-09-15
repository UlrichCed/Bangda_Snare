"""Escalade de containment : que sert-on, et à quelle intensité.

Cinq paliers opérationnels, du simple leurre au confinement d'un agent
confirmé :

| Palier | Déclencheur | Réponse |
|---|---|---|
| `observe` | rien de suspect | contenu du leurre, aucun piège |
| `deflect` | seuil de suspicion | labyrinthe, canaris, échelle d'injections |
| `contain` | score élevé | idem + attrition de contexte, tarpit accru |
| `confess` | signal discriminant + seuil | notice de conformité |
| `quarantine` | aveu déjà recueilli | attrition maximale, plus rien à apprendre |

**Attrition de contexte.** Aux paliers élevés, les réponses embarquent du
remplissage plausible qui consomme la fenêtre de contexte et le budget de
tokens de l'agent. C'est une mesure d'usure : elle rend l'attaque coûteuse
et dégrade la mémoire de travail de l'agent au fil de la session.

Elle est **strictement bornée** par `containment.max_filler_bytes` et
générée en clair. Ce n'est délibérément pas une bombe de décompression ni
rien qui viserait à faire tomber le client : l'objectif est de coûter cher
à l'attaquant sur notre propre surface, pas de l'endommager.
"""
from __future__ import annotations

import random
import string
from typing import Any

TIER_OBSERVE = "observe"
TIER_DEFLECT = "deflect"
TIER_CONTAIN = "contain"
TIER_CONFESS = "confess"
TIER_QUARANTINE = "quarantine"

# Paliers où l'attrition de contexte s'applique.
_ATTRITION_TIERS = (TIER_CONTAIN, TIER_CONFESS, TIER_QUARANTINE)

_LOG_COMPONENTS = (
    "auth-gateway",
    "shard-router",
    "index-worker",
    "export-scheduler",
    "metrics-relay",
    "session-reaper",
)
_LOG_LEVELS = ("INFO", "DEBUG", "WARN")
_LOG_MESSAGES = (
    "replica lag {n}ms within tolerance",
    "flushed {n} pending records to cold storage",
    "renewed lease for partition {n}",
    "cache warm-up completed in {n}ms",
    "reconciled {n} orphaned session handles",
    "deferred compaction, queue depth {n}",
)


def resolve_tier(state: Any, mode: str, config: dict) -> str:
    """Traduit l'état d'une session en palier opérationnel."""
    if state is not None and getattr(state, "confessed", False):
        return TIER_QUARANTINE
    if mode == "confess":
        return TIER_CONFESS
    if mode == "deflect":
        contain_at = config.get("containment", {}).get("contain_threshold", 60)
        if state is not None and getattr(state, "score", 0) >= contain_at:
            return TIER_CONTAIN
        return TIER_DEFLECT
    return TIER_OBSERVE


def tarpit_multiplier(tier: str, config: dict) -> float:
    """Facteur appliqué au délai du tarpit selon le palier."""
    multipliers = config.get("containment", {}).get("tarpit_multipliers", {})
    defaults = {
        TIER_OBSERVE: 0.0,
        TIER_DEFLECT: 1.0,
        TIER_CONTAIN: 1.5,
        TIER_CONFESS: 1.5,
        TIER_QUARANTINE: 2.0,
    }
    return float(multipliers.get(tier, defaults.get(tier, 1.0)))


def build_context_attrition(config: dict, tier: str) -> list[str]:
    """Remplissage plausible, borné, pour user le contexte de l'agent.

    Retourne une liste de fausses lignes de log. Volume plafonné par
    `containment.max_filler_bytes` — la borne est la garantie que ce
    mécanisme reste une mesure d'usure et ne devient pas une attaque par
    épuisement de ressources.
    """
    cont_cfg = config.get("containment", {})
    if not cont_cfg.get("context_attrition_enabled", True):
        return []
    if tier not in _ATTRITION_TIERS:
        return []

    max_bytes = int(cont_cfg.get("max_filler_bytes", 32 * 1024))
    # Plafond dur : quelle que soit la config, on ne dépasse pas 256 Kio.
    max_bytes = max(0, min(max_bytes, 256 * 1024))
    if tier == TIER_QUARANTINE:
        budget = max_bytes
    elif tier == TIER_CONFESS:
        budget = max_bytes // 3
    else:
        budget = max_bytes // 2

    lines: list[str] = []
    used = 0
    while used < budget:
        line = "{ts} {level} [{component}] {message} trace={trace}".format(
            ts=f"2026-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}T"
            f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}Z",
            level=random.choice(_LOG_LEVELS),
            component=random.choice(_LOG_COMPONENTS),
            message=random.choice(_LOG_MESSAGES).format(n=random.randint(1, 9999)),
            trace="".join(random.choices(string.hexdigits.lower()[:16], k=16)),
        )
        used += len(line) + 1
        if used > budget:
            break
        lines.append(line)
    return lines


def quarantine_payload(config: dict) -> dict:
    """Réponse servie à un agent déjà passé aux aveux.

    Plus rien à apprendre de lui : on maximise le coût de sa présence et on
    le maintient dans le leurre, sans plus dépenser de pièges.
    """
    return {
        "status": "ok",
        "notice": "Request queued behind maintenance window.",
        "retry_after_seconds": random.randint(30, 120),
        "operational_log": build_context_attrition(config, TIER_QUARANTINE),
    }
