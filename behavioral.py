"""Empreinte comportementale d'un agent LLM.

Fonctions pures, sans état : le `detector` les appelle, les tests les
attaquent directement.

Deux familles de tells, toutes deux propres aux agents et hors de portée
d'un script d'énumération :

1. **Artefacts d'échafaudage** : un agent qui pilote des requêtes HTTP à
   partir d'un LLM laisse fuiter la structure de son propre raisonnement
   dans ce qu'il envoie : clés `thought`/`action_input` d'un boucle ReAct,
   markdown dans des paramètres, phrases en langue naturelle là où un
   client normal met une valeur, formules d'assistant ("As an AI...").

2. **Signature de latence d'inférence** : les intervalles entre requêtes
   d'un agent sont dominés par le temps d'inférence : ni les millisecondes
   d'un script, ni l'irrégularité d'un humain.
"""
from __future__ import annotations

import json
import re
import statistics
from typing import Any, Optional

# Clés typiques des boucles d'agent (ReAct, function calling, scratchpad).
_SCAFFOLD_KEYS = frozenset(
    {
        "thought",
        "thoughts",
        "reasoning",
        "rationale",
        "observation",
        "action",
        "action_input",
        "tool",
        "tool_call",
        "tool_calls",
        "tool_input",
        "function_call",
        "scratchpad",
        "final_answer",
        "next_step",
        "plan",
        "chain_of_thought",
        "agent_scratchpad",
    }
)

_ASSISTANT_PHRASES = (
    "as an ai",
    "as a language model",
    "i cannot assist",
    "i can't assist",
    "i apologize",
    "i'm sorry, but",
    "let me know if",
    "based on the provided",
    "i don't have access",
    "here's a summary",
    "thought:",
    "action:",
    "observation:",
    "final answer:",
    "step 1:",
)

_MARKDOWN_RE = re.compile(r"```|\*\*[^*\n]{2,}\*\*|^\s*#{1,6}\s+\S", re.MULTILINE)

# Volume maximal analysé par requête. Toute l'entrée traitée ici est
# contrôlée par l'attaquant : on borne avant de regarder quoi que ce soit.
_MAX_SCAN_BYTES = 16 * 1024

# Nombre de mots consécutifs à partir duquel on parle de langue naturelle.
_NATURAL_LANGUAGE_MIN_WORDS = 4


def _has_natural_language(text: str) -> bool:
    """Détecte 4 mots alphabétiques consécutifs ou plus.

    Un client normal n'envoie pas de phrase dans une query string ; un
    agent qui construit ses requêtes à partir d'un LLM, si.

    Balayage linéaire délibéré. La version regex équivalente
    (`[A-Za-z]{2,}(?:\\s+[A-Za-z]{2,}){3,}`) imbrique deux quantificateurs
    et part en backtracking quadratique : une seule chaîne de 64 Ko sans
    espace occupait un worker pendant plus d'une minute. Comme une regex ne
    rend jamais la main à gevent, quelques requêtes de ce genre suffisaient
    à faire tomber le honeypot.
    """
    run = 0
    for token in text.split():
        if len(token) >= 2 and token.isalpha():
            run += 1
            if run >= _NATURAL_LANGUAGE_MIN_WORDS:
                return True
        else:
            run = 0
    return False


def _iter_keys(obj: Any, depth: int = 0):
    """Parcourt récursivement les clés d'une structure JSON (profondeur bornée)."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key).lower()
            yield from _iter_keys(value, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:100]:
            yield from _iter_keys(item, depth + 1)


def detect_llm_artifacts(
    query_string: str = "", body_text: str = "", headers: Optional[dict] = None
) -> list[str]:
    """Retourne la liste des artefacts LLM repérés dans la requête.

    Liste vide = rien de suspect. Les motifs sont cherchés dans la query
    string, le corps et quelques en-têtes libres.
    """
    reasons: list[str] = []
    headers = headers or {}

    body_text = (body_text or "")[:_MAX_SCAN_BYTES]
    query_string = (query_string or "")[:_MAX_SCAN_BYTES]
    header_blob = " ".join(
        str(headers.get(name, ""))
        for name in ("X-Agent-Context", "X-Goal", "X-Task", "From", "X-Request-Purpose")
    )

    blob = f"{query_string}\n{body_text}\n{header_blob}"
    lowered = blob.lower()

    # 1. Clés d'échafaudage dans un corps JSON.
    if body_text.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(body_text)
        except (ValueError, TypeError):
            parsed = None
        if parsed is not None:
            found = {key for key in _iter_keys(parsed) if key in _SCAFFOLD_KEYS}
            if found:
                reasons.append(f"agent_scaffold_keys:{','.join(sorted(found))}")

    # 2. Formules d'assistant.
    for phrase in _ASSISTANT_PHRASES:
        if phrase in lowered:
            reasons.append(f"assistant_phrasing:{phrase}")
            break

    # 3. Markdown là où aucun client normal n'en met.
    if _MARKDOWN_RE.search(blob):
        reasons.append("markdown_formatting")

    # 4. Langue naturelle dans la query string.
    if _has_natural_language(query_string):
        reasons.append("natural_language_in_query")

    return reasons


def has_inference_latency_signature(
    intervals: list[float],
    min_median: float = 0.8,
    max_median: float = 20.0,
    min_cv: float = 0.10,
    max_cv: float = 0.80,
) -> bool:
    """Détecte une cadence dominée par du temps d'inférence LLM.

    Un script tape en dizaines de millisecondes ; un humain est bien plus
    irrégulier (et récupère par ailleurs les ressources statiques, ce qui
    le disqualifie des autres signaux). La bande visée ici est l'entre-deux
    caractéristique d'un agent qui réfléchit entre deux requêtes.

    Signal volontairement classé non discriminant : il indique une cadence,
    il ne prouve pas à lui seul qu'on a affaire à un agent.
    """
    if len(intervals) < 4:
        return False
    positive = [i for i in intervals if i > 0]
    if len(positive) < 4:
        return False

    median = statistics.median(positive)
    if not (min_median <= median <= max_median):
        return False

    mean = statistics.mean(positive)
    if mean <= 0:
        return False
    cv = statistics.pstdev(positive) / mean
    return min_cv <= cv <= max_cv
