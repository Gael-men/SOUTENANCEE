"""
Lecteur Wazuh en temps reel.

Va chercher, a intervalle regulier, les NOUVELLES alertes de Wazuh dans
WSL (/var/ossec/logs/alerts/alerts.json, lisible seulement par root), les
traduit au format du prototype et les fait passer dans la meme chaine que
Suricata (detection -> decision -> reponse -> incident -> base).

Wazuh surveille l'INTERIEUR des machines (authentification, comptes,
privileges, integrite des fichiers), la ou Suricata surveille le reseau.
"""

import os
import json
import subprocess
from datetime import datetime

from detection import detecter
from decision import decider
from response import execute
from incidents import creer_incident
from database import (init_db, save_incident,
                      trouver_incident_actif, incrementer_occurrence)

CHEMIN_ALERTS_WSL = "/var/ossec/logs/alerts/alerts.json"
CHEMIN_ETAT_WAZUH = ".etat_wazuh.json"


def _offset():
    if os.path.exists(CHEMIN_ETAT_WAZUH):
        try:
            with open(CHEMIN_ETAT_WAZUH, encoding="utf-8") as f:
                return json.load(f).get("offset", 0)
        except (json.JSONDecodeError, OSError):
            return 0
    return 0


def _sauver_offset(valeur):
    with open(CHEMIN_ETAT_WAZUH, "w", encoding="utf-8") as f:
        json.dump({"offset": valeur}, f)


def _taille():
    try:
        r = subprocess.run(
            ["wsl", "-u", "root", "stat", "-c", "%s", CHEMIN_ALERTS_WSL],
            capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip().isdigit():
            return int(r.stdout.strip())
    except Exception:
        pass
    return 0


def _lire_depuis(offset):
    try:
        r = subprocess.run(
            ["wsl", "-u", "root", "tail", "-c", "+" + str(offset + 1), CHEMIN_ALERTS_WSL],
            capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return ""


def reinitialiser_offset():
    """Place le marqueur a la fin du fichier (ignore l'historique Wazuh)."""
    _sauver_offset(_taille())


def _classer_wazuh(regle, texte_complet=""):
    """Traduit une regle Wazuh en (scenario, confiance brute).

    Meme classement que sources_reelles._classer_wazuh, pour que les
    deux chemins de collecte donnent le meme resultat pour la meme
    alerte (voir le rapport de concordance).
    Corrections : "root" seul n'est plus teste en sous-chaine, sinon
    le groupe "rootcheck" declenchait a tort un 0,95 critique pour
    toutes les alertes rootcheck. "login" / "pam" seuls ne suffisent
    plus a classer en force brute (une ouverture de session PAM
    legitime n'est pas une attaque) : il faut un groupe
    d'echec d'authentification explicite. Le journal complet
    (full_log) est examine pour detecter un compte uid=0 / backdoor.
    """
    niveau = regle.get("level", 0)
    texte = " ".join(regle.get("groups", []) or []).lower() + " " \
        + (regle.get("description", "") or "").lower() + " " \
        + (texte_complet or "").lower()

    # Elevation de privileges / compte avec uid 0 / backdoor (le plus grave)
    if "uid=0" in texte or "uid 0" in texte or "backdoor" in texte:
        return "suspicious_process", 0.95
    if "privilege" in texte or "sudo" in texte:
        return "suspicious_process", 0.95
    # Creation ou modification de compte
    if "adduser" in texte or "account_changed" in texte or "useradd" in texte \
            or "new user" in texte or "added to group" in texte \
            or "new group" in texte:
        return "suspicious_process", 0.80
    # Echec d'authentification (force brute cote machine)
    if "authentication_fail" in texte or "invalid_login" in texte \
            or "win_authentication_failed" in texte \
            or "authentication_failures" in texte \
            or "failed password" in texte:
        return "bruteforce", min(max(niveau / 15.0, 0.60), 0.99)
    # Integrite de fichiers
    if "syscheck" in texte:
        return "sensitive_file_change", min(max(niveau / 15.0, 0.60), 0.95)
    # Par defaut
    return "suspicious_process", round(min(niveau / 15.0, 0.99), 2)


def ingerer_wazuh(verbeux=False):
    init_db()
    taille = _taille()
    if taille == 0:
        return 0
    offset = _offset()
    if offset > taille:
        offset = 0

    contenu = _lire_depuis(offset)
    nb = 0
    for ligne in contenu.splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            enr = json.loads(ligne)
        except json.JSONDecodeError:
            continue

        regle = enr.get("rule", {})
        if regle.get("level", 0) < 3:   # ignore le bruit de fond
            continue

        scenario, confiance = _classer_wazuh(regle, enr.get("full_log", ""))
        source = enr.get("data", {}).get("srcip") \
            or enr.get("agent", {}).get("name", "hote-local")
        description = regle.get("description", "Alerte Wazuh")

        evenement = {
            "scenario": scenario,
            "description": description,
            "confidence_brute": confiance,
            "source": source,
            "origine": "Wazuh",
        }
        analyse = detecter(evenement)
        choix = decider(analyse)

        existant = trouver_incident_actif(
            analyse["scenario"], analyse.get("description"), source)
        if existant:
            incrementer_occurrence(existant[0], datetime.now().isoformat())
            nb += 1
            continue

        incident = creer_incident(analyse, choix)
        if choix["decision"] == "respond":
            incident["reponse_log"] = execute(choix["action"], source)
        incident["id"] = save_incident(incident)
        nb += 1
        if verbeux:
            print(f"[WAZUH {incident['id']}] {description} "
                  f"-> {incident['severite']} / {incident['decision']}")

    _sauver_offset(taille)
    return nb
