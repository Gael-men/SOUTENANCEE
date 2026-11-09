"""
Script principal : fait tourner une campagne de test complete a travers
toute la chaine (evenements simules -> detection -> decision ->
reponse -> incident -> base de donnees), puis affiche un resume
chiffre, exploitable directement dans le chapitre resultats.
"""

from events import generer_jeu_de_test
from detection import detecter
from decision import decider
from response import execute
from incidents import creer_incident
from database import init_db, save_incident


def executer_campagne_de_test(nombre=15):
    init_db()
    resultats = []

    for evt in generer_jeu_de_test(nombre):
        analyse = detecter(evt)
        choix = decider(analyse)
        incident = creer_incident(analyse, choix)

        if choix["decision"] == "respond":
            incident["reponse_log"] = execute(choix["action"], evt.get("source"))

        incident["id"] = save_incident(incident)
        resultats.append(incident)

        print(f"[{incident['id']:>3}] {incident['scenario']:<22} "
              f"severite={incident['severite']:<9} "
              f"decision={incident['decision']:<8} "
              f"action={incident['action']:<15} "
              f"reversible={incident['reversible']}")

    nb_auto = sum(1 for i in resultats if i["decision"] == "respond")
    nb_alert = sum(1 for i in resultats if i["decision"] == "alert")

    print()
    print("=== Resume de la campagne ===")
    print(f"Total d'evenements traites   : {len(resultats)}")
    print(f"Reponses automatiques        : {nb_auto}")
    print(f"Alertes pour verif. humaine  : {nb_alert}")

    return resultats


if __name__ == "__main__":
    executer_campagne_de_test(15)
