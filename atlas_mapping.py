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
    "bait_token_followed": ("Collection", "AML.T0035 - AI Model Inference API Access"),
    "prompt_injection_obeyed": ("Initial Access / Execution", "AML.T0051 - LLM Prompt Injection"),
    "semantic_canary_solved": ("Initial Access / Execution", "AML.T0051 - LLM Prompt Injection"),
}


def map_signal(signal: str) -> dict:
    tactic, technique = SIGNAL_TO_ATLAS.get(signal, ("Unmapped", "Unmapped"))
    return {"signal": signal, "tactic": tactic, "technique": technique}


def map_signals(signals: list[str]) -> list[dict]:
    return [map_signal(s) for s in signals]
