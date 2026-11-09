"""
Outil de demonstration : capture, attaque par attaque, la reaction de la
plateforme a partir des VRAIES alertes de Suricata (eve.json).

Principe : Suricata tourne en continu et ecrit ses alertes dans eve.json.
Cet outil ne lit QUE les nouvelles alertes depuis son dernier passage
(grace a un marqueur de position enregistre dans .etat_demo.json). Ainsi,
chaque fois que tu lances une attaque puis cet outil, seuls les incidents
correspondant a CETTE attaque apparaissent : l'etat du tableau de bord
evolue attaque par attaque.

Usage :
    python demo_attaque.py reset   -> vide le tableau de bord et ignore
                                       tout l'historique de eve.json
                                       (a faire une fois, au debut)
    python demo_attaque.py         -> ingere les nouvelles alertes depuis
                                       la derniere fois (a faire apres
                                       chaque attaque)
"""

import os
import sys
import json
import sqlite3

from config import DB_NAME
from detection import detecter
from decision import decider
from response import execute
from incidents import creer_incident
from datetime import datetime
from database import (init_db, save_incident,
                      trouver_incident_actif, incrementer_occurrence)

CHEMIN_EVE = r"C:\Program Files\Suricata\log\eve.json"
CHEMIN_ETAT = ".etat_demo.json"

# Table de correspondance signature -> (scenario, confiance brute).
# Reglee pour la demonstration : le ping produit une alerte faible,
# le brute-force une alerte critique (reponse automatique). Toute
# signature non listee (ex: DNS) est ignoree pour ne pas polluer la demo.
REGLES_DEMO = [
    ("brute force telnet", ("bruteforce", 0.95)),
    ("brute force ssh",    ("bruteforce", 0.95)),
    ("telnet",             ("bruteforce", 0.95)),
    ("ssh",                ("bruteforce", 0.95)),
    ("scan",               ("suspicious_process", 0.80)),
    ("ping",               ("suspicious_process", 0.45)),
]


def _classer(signature):
    texte = (signature or "").lower()
    for mot_cle, (scenario, confiance) in REGLES_DEMO:
        if mot_cle in texte:
            return scenario, confiance
    return None, None


def _charger_offset():
    if os.path.exists(CHEMIN_ETAT):
        try:
            with open(CHEMIN_ETAT, encoding="utf-8") as f:
                return json.load(f).get("offset_eve", 0)
        except (json.JSONDecodeError, OSError):
            return 0
    return 0


def _sauver_offset(offset):
    with open(CHEMIN_ETAT, "w", encoding="utf-8") as f:
        json.dump({"offset_eve": offset}, f)


def _taille_eve():
    return os.path.getsize(CHEMIN_EVE) if os.path.exists(CHEMIN_EVE) else 0


def reinitialiser():
    init_db()
    conn = sqlite3.connect(DB_NAME, timeout=5)
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")
    conn.commit()
    conn.close()
    # On place le marqueur a la fin du fichier actuel : tout l'historique
    # est ignore, seules les attaques a VENIR seront capturees.
    _sauver_offset(_taille_eve())
    try:
        from wazuh_temps_reel import reinitialiser_offset as _reset_wazuh
        _reset_wazuh()
    except Exception:
        pass
    print("Demonstration reinitialisee.")
    print("Tableau de bord vide, historique ignore.")
    print("Lance une attaque, puis relance : python demo_attaque.py")


def ingerer_nouvelles_alertes(verbeux=True):
    init_db()
    offset = _charger_offset()
    taille = _taille_eve()
    if taille < offset:          # fichier recree / tronque
        offset = 0

    with open(CHEMIN_EVE, "rb") as f:
        f.seek(offset)
        donnees = f.read()
    nouvel_offset = offset + len(donnees)

    nb = 0
    for ligne in donnees.decode("utf-8", errors="ignore").splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            enr = json.loads(ligne)
        except json.JSONDecodeError:
            continue
        if enr.get("event_type") != "alert":
            continue

        signature = enr.get("alert", {}).get("signature", "")
        scenario, confiance = _classer(signature)
        if scenario is None:
            continue

        evenement = {
            "scenario": scenario,
            "description": signature,
            "confidence_brute": confiance,
            "source": enr.get("src_ip", "inconnue"),
            "origine": "Suricata",
        }
        analyse = detecter(evenement)
        choix = decider(analyse)

        # Regroupement : si un incident actif de meme nature existe deja,
        # on incremente son compteur au lieu de creer une nouvelle ligne.
        existant = trouver_incident_actif(
            analyse["scenario"], analyse.get("description"), evenement["source"])
        if existant:
            incrementer_occurrence(existant[0], datetime.now().isoformat())
            nb += 1
            if verbeux:
                print(f"[{existant[0]:>3}] {signature} (regroupe : +1 occurrence)")
            continue

        incident = creer_incident(analyse, choix)
        if choix["decision"] == "respond":
            incident["reponse_log"] = execute(choix["action"], evenement["source"])
        incident["id"] = save_incident(incident)
        nb += 1

        if verbeux:
            print(f"[{incident['id']:>3}] {signature}")
            print(f"      -> gravite={incident['severite']}, "
                  f"decision={incident['decision']}, "
                  f"action={incident['action']}, "
                  f"reversible={incident['reversible']}")

    _sauver_offset(nouvel_offset)
    if verbeux:
        if nb == 0:
            print("Aucune nouvelle alerte exploitable depuis la derniere fois.")
        else:
            print(f"\n{nb} nouvel(aux) incident(s) ajoute(s). Rafraichis le tableau de bord.")
    return nb


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reset":
        reinitialiser()
    else:
        ingerer_nouvelles_alertes()
