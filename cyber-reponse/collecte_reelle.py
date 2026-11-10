"""
Collecte reelle : fait tourner toute la chaine du prototype a partir des
VRAIES alertes produites par Suricata (IDS reseau) et Wazuh (SIEM hote),
au lieu du generateur simule.

Chaine : sources reelles -> detection -> decision -> reponse -> incident
-> base de donnees. C'est la meme chaine que main.py ; seule la source
des evenements change. Les incidents enregistres apparaissent ensuite
dans le tableau de bord (app.py), exactement comme ceux de la campagne
simulee.

Avant de lire Wazuh, ce script depose une copie lisible de son fichier
d'alertes (qui, dans WSL2, appartient a l'utilisateur systeme "wazuh").
"""

import subprocess

from datetime import datetime

from detection import detecter
from decision import decider
from response import execute
from incidents import creer_incident
from database import (init_db, save_incident,
                      trouver_incident_actif, incrementer_occurrence)
from sources_reelles import lire_tous_les_evenements, CHEMIN_ALERTS_WAZUH


def rafraichir_copie_wazuh():
    """
    Copie /var/ossec/logs/alerts/alerts.json (dans WSL2, lisible seulement
    par root) vers une copie locale lisible par le prototype.
    Sans echec bloquant : si WSL ou Wazuh n'est pas disponible, on continue
    avec Suricata seul.
    """
    try:
        resultat = subprocess.run(
            ["wsl", "-u", "root", "cat", "/var/ossec/logs/alerts/alerts.json"],
            capture_output=True, text=True, timeout=30,
        )
        if resultat.returncode == 0 and resultat.stdout.strip():
            with open(CHEMIN_ALERTS_WAZUH, "w", encoding="utf-8") as f:
                f.write(resultat.stdout)
            print("Copie des alertes Wazuh : OK")
        else:
            print("Copie des alertes Wazuh : aucune donnee (Wazuh non demarre ?)")
    except Exception as exc:
        print(f"Copie des alertes Wazuh : indisponible ({exc})")


def executer_collecte_reelle():
    init_db()
    rafraichir_copie_wazuh()

    evenements = lire_tous_les_evenements()
    print(f"\n{len(evenements)} evenement(s) reel(s) collecte(s).\n")

    resultats = []
    nb_regroupes = 0
    for evt in evenements:
        analyse = detecter(evt)
        choix = decider(analyse)

        # Regroupement (memoire, section 2.3.4) : un evenement de meme
        # nature qu'un incident encore actif incremente son compteur
        # au lieu de creer une nouvelle ligne. Sans cela, relancer
        # ce script relisait tout l'historique et dupliquait les
        # incidents. Meme regle que dans demo_attaque.py et
        # wazuh_temps_reel.py.
        existant = trouver_incident_actif(
            analyse["scenario"], analyse.get("description"), evt.get("source"))
        if existant:
            incrementer_occurrence(existant[0], datetime.now().isoformat())
            nb_regroupes += 1
            continue

        incident = creer_incident(analyse, choix)

        if choix["decision"] == "respond":
            incident["reponse_log"] = execute(choix["action"], evt.get("source"))

        incident["id"] = save_incident(incident)
        resultats.append(incident)

        origine = evt.get("origine", "?")
        print(f"[{incident['id']:>3}] {origine:<9} {incident['scenario']:<22} "
              f"severite={incident['severite']:<9} "
              f"decision={incident['decision']:<8} "
              f"action={incident['action']}")

    nb_auto = sum(1 for i in resultats if i["decision"] == "respond")
    nb_alert = sum(1 for i in resultats if i["decision"] == "alert")
    nb_suricata = sum(1 for e in evenements if e.get("origine") == "Suricata")
    nb_wazuh = sum(1 for e in evenements if e.get("origine") == "Wazuh")

    print()
    print("=== Resume de la collecte reelle ===")
    print(f"Evenements Suricata (reseau) : {nb_suricata}")
    print(f"Evenements Wazuh (hote)      : {nb_wazuh}")
    print(f"Total traites                : {len(evenements)}")
    print(f"Nouveaux incidents crees     : {len(resultats)}")
    print(f"Evenements regroupes         : {nb_regroupes}")
    print(f"Reponses automatiques        : {nb_auto}")
    print(f"Alertes pour verif. humaine  : {nb_alert}")

    return resultats


if __name__ == "__main__":
    executer_collecte_reelle()
