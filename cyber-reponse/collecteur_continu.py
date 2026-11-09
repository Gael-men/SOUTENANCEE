"""
Collecteur continu : surveille en permanence LES DEUX sources de securite
et injecte leurs alertes en temps reel dans le systeme.

  - Suricata  : surveillance du RESEAU (trafic, scans, brute-force reseau)
  - Wazuh     : surveillance des MACHINES (authentification, comptes,
                privileges, integrite des fichiers)

C'est le fonctionnement d'un vrai SIEM : detection, decision et reponse en
temps reel, a partir du reseau ET de l'interieur des postes.

Usage : python collecteur_continu.py
"""

import time
from datetime import datetime

from demo_attaque import ingerer_nouvelles_alertes   # Suricata (reseau)
from wazuh_temps_reel import ingerer_wazuh            # Wazuh (hote)

INTERVALLE_SECONDES = 3

if __name__ == "__main__":
    print("Collecteur continu demarre : Suricata (reseau) + Wazuh (hote) en temps reel.")
    print(f"Verification toutes les {INTERVALLE_SECONDES} secondes. Ctrl+C pour arreter.\n")
    while True:
        try:
            nb_reseau = ingerer_nouvelles_alertes(verbeux=False)
        except Exception as exc:
            nb_reseau = 0
            print(f"(Suricata - erreur ignoree : {exc})")
        try:
            nb_hote = ingerer_wazuh(verbeux=False)
        except Exception as exc:
            nb_hote = 0
            print(f"(Wazuh - erreur ignoree : {exc})")

        if nb_reseau or nb_hote:
            heure = datetime.now().strftime("%H:%M:%S")
            print(f"[{heure}] {nb_reseau} reseau (Suricata) + "
                  f"{nb_hote} hote (Wazuh) = {nb_reseau + nb_hote} incident(s).")
        time.sleep(INTERVALLE_SECONDES)
