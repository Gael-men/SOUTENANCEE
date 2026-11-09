"""
Moteur de detection (module M2).

Recoit un evenement brut (tel que produit par events.py ou, dans une
version future, par une vraie source de logs) et calcule deux
informations que le moteur de decision utilisera ensuite :
  - la confiance : le degre de certitude que l'evenement est reel
  - la severite : la gravite de l'evenement s'il se confirme

C'est ce calcul qui fait de ce module un veritable moteur de
detection, et non une simple transmission de valeurs recues toutes
faites.
"""

# Seuils de severite par scenario. Cles = scenario, valeurs = liste de
# (seuil_min_confiance, niveau_de_severite), du plus eleve au plus bas.
REGLES_SEVERITE = {
    "bruteforce": [
        (0.90, "critique"),
        (0.75, "elevee"),
        (0.60, "moyenne"),
        (0.0, "faible"),
    ],
    "suspicious_process": [
        (0.90, "critique"),
        (0.75, "elevee"),
        (0.55, "moyenne"),
        (0.0, "faible"),
    ],
    "sensitive_file_change": [
        (0.85, "elevee"),
        (0.65, "moyenne"),
        (0.0, "faible"),
    ],
}


def _calculer_severite(scenario, confiance):
    regles = REGLES_SEVERITE.get(scenario, [(0.0, "faible")])
    for seuil, niveau in regles:
        if confiance >= seuil:
            return niveau
    return "faible"


def detecter(evenement):
    """
    Analyse un evenement brut et retourne l'evenement enrichi avec
    "confidence" (confiance retenue par le moteur) et "severite".

    Le champ "realite" (verite terrain, utilise uniquement pour
    l'evaluation) est conserve tel quel et transmis sans etre lu par
    la logique de decision.
    """
    scenario = evenement.get("scenario")
    confiance_brute = evenement.get("confidence_brute", 0)

    # Le moteur retient la confiance brute (arrondie), en reservant la
    # possibilite d'ajouter plus tard une pondération (ex: historique
    # de la source, recurrence de l'evenement) sans toucher au reste
    # de la chaine.
    confiance = round(confiance_brute, 2)
    severite = _calculer_severite(scenario, confiance)

    resultat = dict(evenement)
    resultat["confidence"] = confiance
    resultat["severite"] = severite
    return resultat


if __name__ == "__main__":
    from events import generer_jeu_de_test

    for evt in generer_jeu_de_test(5):
        print(detecter(evt))
