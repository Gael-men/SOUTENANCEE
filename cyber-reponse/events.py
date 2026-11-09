"""
Generateur d'evenements simules.

Chaque evenement represente une situation detectee sur le systeme
d'une PME (tentative de connexion, processus suspect, modification
de fichier sensible). Le champ "realite" indique si l'evenement
correspond a une vraie attaque ou a un cas benin qui ressemble a une
attaque (ex : un administrateur qui se trompe plusieurs fois de mot
de passe).

Ce champ sert UNIQUEMENT a l'evaluation du prototype (calcul du taux
de faux positifs au chapitre resultats) : il n'est jamais transmis au
moteur de detection ni affiche dans le tableau de bord. C'est la
"verite terrain" d'un protocole de test controle.
"""

import random

# Chaque scenario : (nom, description, plage de confiance brute si
# attaque reelle, plage de confiance brute si cas benin)
SCENARIOS = [
    ("bruteforce", "Tentatives de connexion repetees",
     (0.85, 0.99), (0.55, 0.80)),
    ("suspicious_process", "Processus suspect detecte",
     (0.85, 0.98), (0.50, 0.75)),
    ("sensitive_file_change", "Modification d'un fichier sensible",
     (0.70, 0.95), (0.40, 0.65)),
]


def generer_evenement(forcer_attaque=None):
    """
    Genere un evenement simule.

    forcer_attaque : True pour forcer une vraie attaque, False pour
    forcer un cas benin, None pour tirer au hasard (70% d'attaques,
    30% de cas benins : proportion volontairement realiste pour un
    jeu de test, pas un cas d'ecole a 50/50).
    """
    scenario, description, plage_attaque, plage_benin = random.choice(SCENARIOS)

    if forcer_attaque is None:
        est_attaque = random.random() < 0.7
    else:
        est_attaque = forcer_attaque

    plage = plage_attaque if est_attaque else plage_benin
    confiance_brute = round(random.uniform(*plage), 2)

    return {
        "scenario": scenario,
        "description": description,
        "confidence_brute": confiance_brute,
        "source": f"192.168.1.{random.randint(2, 254)}",
        "realite": "attaque" if est_attaque else "benin",
    }


def generer_jeu_de_test(nombre=15):
    """Genere un jeu de plusieurs evenements pour une campagne de test."""
    return [generer_evenement() for _ in range(nombre)]


if __name__ == "__main__":
    for evt in generer_jeu_de_test(5):
        print(evt)
