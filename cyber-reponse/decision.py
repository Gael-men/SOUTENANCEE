"""
Moteur de decision (module M3).

Prend un evenement deja analyse par le moteur de detection (qui a
calcule "confidence" et "severite") et decide de l'action a mener :
reponse automatique si l'evenement est a la fois tres probable et
grave, sinon alerte necessitant une verification humaine.

Regle du memoire (section 2.3.3, deja soumis) : une reponse
automatique n'est declenchee que si l'action est REVERSIBLE.
Le blocage de la source (block_source) est reversible.
L'arret d'un processus (stop_process) ne l'est PAS : il est donc
propose dans la raison de l'alerte, journalise, mais reserve a une
decision humaine explicite. Il ne doit jamais etre declenche
automatiquement par ce module.
"""

from config import SEUIL_CONFIANCE_AUTO, ACTIONS_REVERSIBLES

# Action de reponse AUTOMATIQUE associee a chaque scenario.
# Seules les actions presentes dans config.ACTIONS_REVERSIBLES
# peuvent figurer ici. "stop_process" en est volontairement absent.
ACTIONS_PAR_SCENARIO = {
    "bruteforce": "block_source",
}

# Action proposee (mais non declenchee automatiquement) quand
# l'evenement est critique et que l'action associee n'est pas
# reversible. Elle est mentionnee dans la raison, pour que
# l'operateur sache ce qui est envisage, sans que le systeme
# l'execute a sa place.
ACTIONS_PROPOSEES_NON_REVERSIBLES = {
    "suspicious_process": "stop_process",
}

SEVERITES_CRITIQUES = ("elevee", "critique")


def decider(evenement_analyse):
    scenario = evenement_analyse.get("scenario")
    confiance = evenement_analyse.get("confidence", 0)
    severite = evenement_analyse.get("severite", "faible")

    action_possible = ACTIONS_PAR_SCENARIO.get(scenario)

    # Garde-fou : meme si la table ci-dessus etait modifiee par
    # erreur, une action non reversible ne peut pas partir en
    # reponse automatique.
    if (
        action_possible
        and action_possible in ACTIONS_REVERSIBLES
        and confiance >= SEUIL_CONFIANCE_AUTO
        and severite in SEVERITES_CRITIQUES
    ):
        description = evenement_analyse.get("description", scenario)
        return {
            "decision": "respond",
            "action": action_possible,
            "reason": f"{description} confirme (confiance {confiance}, severite {severite})",
        }

    # Cas non reversible, meme critique et sur : alerte humaine.
    # La decision d'arret est journalisee dans la raison, comme
    # dans le Tableau 4 du memoire (scenario 5), sans etre executee.
    action_proposee = ACTIONS_PROPOSEES_NON_REVERSIBLES.get(scenario)
    if action_proposee and confiance >= SEUIL_CONFIANCE_AUTO and severite in SEVERITES_CRITIQUES:
        return {
            "decision": "alert",
            "action": "notify_admin",
            "reason": (
                f"Evenement de severite {severite} necessitant une verification humaine "
                f"(confiance {confiance}) : arret du processus propose "
                f"({action_proposee}), action non reversible reservee a une decision humaine"
            ),
        }

    return {
        "decision": "alert",
        "action": "notify_admin",
        "reason": f"Evenement de severite {severite} necessitant une verification humaine",
    }


if __name__ == "__main__":
    from events import generer_jeu_de_test
    from detection import detecter

    for evt in generer_jeu_de_test(5):
        print(decider(detecter(evt)))
