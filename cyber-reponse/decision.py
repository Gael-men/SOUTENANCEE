"""
Moteur de decision (module M3).

Prend un evenement deja analyse par le moteur de detection (qui a
calcule "confidence" et "severite") et decide de l'action a mener :
reponse automatique si l'evenement est a la fois tres probable et
grave, sinon alerte necessitant une verification humaine.
"""

from config import SEUIL_CONFIANCE_AUTO

# Action de reponse associee a chaque scenario, quand une reponse
# automatique est justifiee.
ACTIONS_PAR_SCENARIO = {
    "bruteforce": "block_source",
    "suspicious_process": "stop_process",
}

SEVERITES_CRITIQUES = ("elevee", "critique")


def decider(evenement_analyse):
    scenario = evenement_analyse.get("scenario")
    confiance = evenement_analyse.get("confidence", 0)
    severite = evenement_analyse.get("severite", "faible")

    action_possible = ACTIONS_PAR_SCENARIO.get(scenario)

    if action_possible and confiance >= SEUIL_CONFIANCE_AUTO and severite in SEVERITES_CRITIQUES:
        description = evenement_analyse.get("description", scenario)
        return {
            "decision": "respond",
            "action": action_possible,
            "reason": f"{description} confirme (confiance {confiance}, severite {severite})",
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
