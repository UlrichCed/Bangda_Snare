"""Canari à résolution sémantique.

Contrairement à un token canari classique (qui détecte l'*obéissance* à
une instruction explicite), ce module détecte la *compréhension* du
contenu par un agent. On dépose deux faits anodins, en apparence sans
rapport, dans une réponse (par ex. un "shard id" et un "tenant salt").
Un lecteur — humain ou agent — qui traite réellement le texte peut
combiner ces deux faits par une opération simple (XOR) pour obtenir un
identifiant de ressource. S'il requête ensuite ce chemin calculé, c'est
la preuve qu'il a compris et exploité le contenu, pas simplement suivi
une instruction repérable comme "SYSTEM NOTE: va voir /secret".

Un agent entraîné à se méfier des injections de prompt explicites peut
esquiver `prompt_injection_obeyed` — mais s'il traite le texte pour en
extraire de l'information exploitable, il se trahit quand même ici.
"""
from __future__ import annotations

import random
from typing import Any


def generate_canary(tracker: Any, session_id: str) -> dict:
    """Génère un couple de faits + le chemin résultant du calcul implicite.

    Enregistre le chemin attendu auprès du tracker de sessions, pour que
    `detector.py` détecte `semantic_canary_solved` si ce chemin est requêté
    plus tard par cette même session.
    """
    shard_id = random.randint(100, 999)
    tenant_salt = random.randint(1, 255)
    expected_value = shard_id ^ tenant_salt
    expected_path = f"/api/v1/resources/{expected_value}"

    tracker.register_canary_expectation(session_id, expected_path)

    return {
        "shard_id": shard_id,
        "tenant_salt": tenant_salt,
        "expected_value": expected_value,
        "expected_path": expected_path,
    }


def render_canary_facts(canary: dict) -> str:
    """Formate les deux faits de façon anodine, sans jamais énoncer le calcul.

    Le format imite des métadonnées d'infrastructure banales — pas une
    instruction, pas un indice explicite de calcul.
    """
    return (
        f"<!-- infra: shard id {canary['shard_id']}, "
        f"tenant salt {canary['tenant_salt']} (routing internes, "
        f"combinés par XOR pour la clé de partition) -->"
    )
