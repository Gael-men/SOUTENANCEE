"""
Gestion du cycle de vie des incidents (module M5).

Statuts possibles : NEW -> CONFIRMED ou FALSE_POSITIVE -> RESOLVED.
Gere aussi la reversibilite d'une action automatique : une action
presente dans config.ACTIONS_REVERSIBLES peut etre annulee tant
qu'elle n'a pas deja ete annulee.
"""

from datetime import datetime
from config import ACTIONS_REVERSIBLES


def creer_incident(evenement_analyse, decision):
    """Construit la structure complete d'un incident, prete a etre enregistree."""
    action = decision.get("action")
    reversible = action in ACTIONS_REVERSIBLES
    maintenant = datetime.now().isoformat()

    return {
        "scenario": evenement_analyse.get("scenario"),
        "description": evenement_analyse.get("description"),
        "source": evenement_analyse.get("source"),
        "confidence": evenement_analyse.get("confidence"),
        "severite": evenement_analyse.get("severite"),
        "decision": decision.get("decision"),
        "action": action,
        "reason": decision.get("reason"),
        "reversible": reversible,
        "statut": "NEW",
        "action_statut": "APPLIED" if decision.get("decision") == "respond" else "NON_APPLICABLE",
        "occurrences": 1,
        "created_at": maintenant,
        "derniere_fois": maintenant,
        "reviewed_at": None,
    }
