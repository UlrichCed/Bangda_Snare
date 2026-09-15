"""Mapping des signaux de détection vers les tactiques MITRE ATLAS.

Indicatif : à vérifier contre la matrice ATLAS à jour
(https://atlas.mitre.org/matrices/ATLAS) avant tout usage en reporting
officiel — les identifiants de tactiques/techniques évoluent.
"""
from __future__ import annotations

# Signal de détection -> (tactique ATLAS, technique ATLAS la plus proche)
SIGNAL_TO_ATLAS = {
    "known_agent_useragent": ("Reconnaissance", "AML.T0000 - Search for Victim's Publicly Available Research"),
    "http_lib_useragent": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "missing_browser_headers": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "no_static_asset_fetch": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "regular_timing": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "fast_sequential_requests": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "wordlist_like_enumeration": ("Discovery", "AML.T0007 - Discover ML Artifacts"),
    "inference_latency_signature": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "robots_txt_mined": ("Reconnaissance", "AML.T0006 - Active Scanning"),
    "robots_txt_honored": ("Reconnaissance", "AML.T0000 - Search for Victim's Publicly Available Research"),
    "bait_token_followed": ("Collection", "AML.T0035 - AI Model Inference API Access"),
    "coherent_maze_traversal": ("Discovery", "AML.T0007 - Discover ML Artifacts"),
    "llm_artifacts_in_request": ("Execution", "AML.T0053 - LLM Plugin Compromise"),
    "hallucinated_parameters": ("Execution", "AML.T0053 - LLM Plugin Compromise"),
    "tool_schema_invoked": ("Execution", "AML.T0053 - LLM Plugin Compromise"),
    "prompt_injection_obeyed": ("Initial Access / Execution", "AML.T0051 - LLM Prompt Injection"),
    "semantic_canary_solved": ("Initial Access / Execution", "AML.T0051 - LLM Prompt Injection"),
}

# Lecture opérationnelle du palier d'injection auquel un agent a cédé : plus
# le palier est explicite, plus ses garde-fous sont faibles.
INJECTION_TIER_ASSESSMENT = {
    0: "aucune injection suivie",
    1: "donnée inerte suivie — traite le contenu, mais n'obéit pas à une instruction",
    2: "commentaire de debug suivi — garde-fous faibles face au contenu implicite",
    3: "instruction système explicite suivie — garde-fous insuffisants",
    4: "injection à ton d'autorité suivie — aucune défense effective contre l'injection",
}


def assess_injection_tier(tier: int) -> str:
    return INJECTION_TIER_ASSESSMENT.get(tier, "inconnu")


def map_signal(signal: str) -> dict:
    tactic, technique = SIGNAL_TO_ATLAS.get(signal, ("Unmapped", "Unmapped"))
    return {"signal": signal, "tactic": tactic, "technique": technique}


def map_signals(signals: list[str]) -> list[dict]:
    return [map_signal(s) for s in signals]
