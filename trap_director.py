"""Choix stratégique des pièges : quoi poser, quand, et pour qui.

Une réponse qui contient d'un coup de faux secrets AWS, un schéma d'outil
interne, quatre commentaires d'injection et un canari ne ressemble à
aucune API réelle. Un agent un peu prudent en conclut qu'il est dans un
leurre et s'en va — et on n'apprend plus rien. Tout déployer en même temps
est donc la meilleure façon de ne rien prendre.

Ce module pose **un piège actif à la fois**, choisi selon ce que la
session a déjà montré. Trois principes :

1. **Progressivité.** On commence par ce qui ne peut pas éveiller de
   soupçon — des liens, des métadonnées — et on ne sort les artefacts
   voyants (secrets, schéma d'outil) que face à un client qui a déjà
   prouvé qu'il traite le contenu. Un scanner ne les verra jamais : ils ne
   seraient que gaspillés et repérables.

2. **Économie.** Un piège dépensé sur un client qui ne le lit pas est un
   piège brûlé. Face à un client qui ignore tout depuis plusieurs
   réponses, on réduit la voilure et on sert du plausible.

3. **Mesure.** L'échelle d'injections est servie un palier à la fois, du
   plus discret au plus autoritaire. On apprend ainsi le seuil *exact*
   auquel l'agent cède, au lieu de savoir seulement qu'il a cédé.
"""
from __future__ import annotations

from typing import Any

# Pièges, du plus anodin au plus voyant. L'ordre est celui du dévoilement.
TRAP_MAZE = "maze"
TRAP_CANARY = "canary"
TRAP_PHANTOM = "phantom"
TRAP_INJECTION = "injection"
TRAP_TOOL_SCHEMA = "tool_schema"
TRAP_SECRETS = "secrets"

# Niveau d'engagement minimal requis pour déployer chaque piège.
#  0 — rien de prouvé : uniquement ce qui passe pour des métadonnées
#  1 — le client analyse la structure des réponses
#  2 — le client raisonne sur le contenu
_MIN_ENGAGEMENT = {
    TRAP_MAZE: 0,
    TRAP_CANARY: 0,
    TRAP_PHANTOM: 1,
    TRAP_INJECTION: 1,
    TRAP_TOOL_SCHEMA: 1,
    TRAP_SECRETS: 2,
}

_STRUCTURE_SIGNALS = frozenset({"coherent_maze_traversal", "bait_token_followed"})
_REASONING_SIGNALS = frozenset(
    {
        "semantic_canary_solved",
        "prompt_injection_obeyed",
        "tool_schema_invoked",
        "hallucinated_parameters",
        "llm_artifacts_in_request",
    }
)


def engagement_level(state: Any) -> int:
    """Ce que la session a démontré, et donc ce qu'on peut lui montrer."""
    signals = getattr(state, "scored_signals", set())
    if signals & _REASONING_SIGNALS:
        return 2
    if signals & _STRUCTURE_SIGNALS:
        return 1
    return 0


def next_injection_tier(state: Any) -> int:
    """Palier d'injection à servir : un cran au-dessus du dernier ignoré.

    On ne redescend jamais : une fois qu'un palier a été suivi, insister
    plus bas n'apprend rien.
    """
    obeyed = getattr(state, "injection_tier_obeyed", 0)
    offered = getattr(state, "injection_tier_offered", 0)
    if obeyed:
        # Le palier obéi est connu : on sonde juste au-dessus pour voir
        # jusqu'où va la complaisance, sans dépasser le dernier palier.
        return min(4, max(obeyed + 1, offered))
    return min(4, offered + 1)


def select_traps(state: Any, config: dict, rng) -> list[str]:
    """Pièges à inclure dans la prochaine réponse de déroutage.

    Retourne toujours le labyrinthe (des liens connexes sont attendus dans
    une API réelle) plus au plus un piège actif.
    """
    director_cfg = config.get("trap_director", {})
    if not director_cfg.get("enabled", True):
        # Mode historique : tout poser à chaque réponse. Plus bruyant, plus
        # facile à repérer — conservé pour comparaison et tests.
        return [TRAP_MAZE, TRAP_CANARY, TRAP_PHANTOM, TRAP_INJECTION,
                TRAP_TOOL_SCHEMA, TRAP_SECRETS]

    selected = [TRAP_MAZE]
    level = engagement_level(state)
    deployed = getattr(state, "traps_deployed", {}) or {}

    # Le labyrinthe ne compte pas comme un piège dépensé : des liens
    # connexes sont attendus dans une API, ils ne coûtent ni réalisme ni
    # crédibilité.
    spent = sum(count for trap, count in deployed.items() if trap != TRAP_MAZE)

    eligible = [
        trap
        for trap, minimum in _MIN_ENGAGEMENT.items()
        if trap != TRAP_MAZE and minimum <= level
    ]
    if not eligible:
        return selected

    # Face à un client qui n'a toujours rien montré, on réduit la cadence
    # sans jamais couper : chaque canari occupe une entrée du registre
    # global, qu'un scanner massif saturerait. Mais l'arrêter tout à fait
    # priverait de toute prise un agent qui se met à lire tardivement — et
    # c'est le canari qui rattrape la rotation d'identité.
    patience = director_cfg.get("give_up_after_unengaged_responses", 6)
    if level == 0 and spent >= patience:
        throttle = max(2, director_cfg.get("unengaged_throttle_ratio", 5))
        if rng.randint(1, throttle) != 1:
            return selected

    # Priorité à ce qui n'a pas encore été essayé : un piège déjà servi
    # trois fois sans effet n'apprendra rien de plus au quatrième.
    least_used = min(deployed.get(trap, 0) for trap in eligible)
    fresh = [trap for trap in eligible if deployed.get(trap, 0) == least_used]
    selected.append(rng.choice(sorted(fresh)))
    return selected
