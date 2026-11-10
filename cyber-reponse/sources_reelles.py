"""
Pont vers les sources de donnees reelles (module de collecte).

Ce module remplace le generateur simule (events.py) par deux vraies
sources de securite installees et connectees au systeme :

  - Suricata (IDS reseau) : lit le fichier eve.json et en extrait les
    alertes reseau (event_type == "alert").
  - Wazuh (SIEM hote / HIDS) : lit le fichier alerts.json et en extrait
    les alertes systeme (authentification, integrite de fichiers, etc.).

Chaque alerte reelle est traduite dans le MEME format d'evenement que
celui produit par events.py, afin d'etre traitee par la chaine existante
(detection.py -> decision.py -> incidents.py -> database.py) sans aucune
modification de cette chaine.

La traduction repose sur une TABLE DE CORRESPONDANCE explicite entre les
categories d'alertes des outils et les trois scenarios du prototype
(bruteforce, suspicious_process, sensitive_file_change). Cette table est
le coeur de l'integration : elle est volontairement simple et lisible,
pour pouvoir etre expliquee et defendue dans le memoire.

Difference importante avec events.py : les evenements reels n'ont pas de
champ "realite" (verite terrain), puisqu'on ne sait pas a l'avance si une
alerte reelle est un vrai positif ou un faux positif. Ce champ est donc
absent ici, ce qui est normal et conforme a une situation d'exploitation
reelle.

Corrections (memoire deja soumis, code aligne sur le memoire) :
  - le ping est desormais collecte ici aussi (confiance 0,45, comme
    dans demo_attaque.py et le Tableau 4 du memoire) ;
  - le classement Wazuh est le MEME que dans wazuh_temps_reel.py
    (plancher 0,60 pour l'authentification, 0,95 pour sudo /
    privilege / uid=0 / backdoor, 0,80 pour la creation de compte),
    pour qu'une meme alerte ne donne plus deux resultats differents
    selon le chemin de collecte utilise.
"""

import json
import os
import re

# ---------------------------------------------------------------------------
# Chemins par defaut des fichiers de logs des deux sources.
# Adaptables si l'installation differe.
# ---------------------------------------------------------------------------
CHEMIN_EVE_SURICATA = r"C:\Program Files\Suricata\log\eve.json"

# Wazuh tourne dans WSL2 ; son fichier d'alertes appartient a l'utilisateur
# systeme "wazuh" et n'est pas lisible directement. Un petit script
# (voir collecte_reelle.py) en depose une copie lisible a cet endroit.
CHEMIN_ALERTS_WAZUH = "wazuh_alerts.json"


# ---------------------------------------------------------------------------
# SURICATA : correspondance signature reseau -> scenario du prototype
# ---------------------------------------------------------------------------
# Une alerte Suricata dont la signature contient l'un de ces mots-cles est
# rattachee au scenario indique. Les alertes qui ne correspondent a aucun
# mot-cle (ex: requete DNS) sont considerees comme purement informatives
# et NE generent PAS d'incident.
MOTS_CLES_SURICATA = [
    ("telnet", "bruteforce"),
    ("ssh", "bruteforce"),
    ("brute", "bruteforce"),
    ("login", "bruteforce"),
    ("scan", "suspicious_process"),
    ("nmap", "suspicious_process"),
    ("exploit", "suspicious_process"),
    ("malware", "suspicious_process"),
    ("trojan", "suspicious_process"),
    ("shellcode", "suspicious_process"),
    # Reconnaissance par ping : scenario 1 du Tableau 4 du memoire.
    ("ping", "suspicious_process"),
    ("icmp", "suspicious_process"),
]

# Suricata note la gravite de 1 (la plus elevee) a 3 (la plus faible).
# On la traduit en une confiance brute comparable a celle du simulateur.
CONFIANCE_PAR_SEVERITE_SURICATA = {1: 0.95, 2: 0.80, 3: 0.62}

# Confiance fixee pour le ping, comme dans demo_attaque.py :
# 0,45 = gravite faible, alerte simple, aucune reponse automatique.
CONFIANCE_PING = 0.45


def _scenario_suricata(signature):
    texte = (signature or "").lower()
    for mot_cle, scenario in MOTS_CLES_SURICATA:
        if mot_cle in texte:
            return scenario
    return None  # alerte informative, ignoree


def _confiance_suricata(signature, severite_suricata):
    texte = (signature or "").lower()
    if "ping" in texte or "icmp" in texte:
        return CONFIANCE_PING
    return CONFIANCE_PAR_SEVERITE_SURICATA.get(severite_suricata, 0.60)


def lire_evenements_suricata(chemin=CHEMIN_EVE_SURICATA):
    """
    Lit le fichier eve.json de Suricata et renvoie la liste des evenements
    (au format du prototype) correspondant a des alertes exploitables.
    """
    evenements = []
    if not os.path.exists(chemin):
        return evenements

    with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                enregistrement = json.loads(ligne)
            except json.JSONDecodeError:
                continue

            if enregistrement.get("event_type") != "alert":
                continue

            alerte = enregistrement.get("alert", {})
            signature = alerte.get("signature", "")
            scenario = _scenario_suricata(signature)
            if scenario is None:
                continue

            severite_suricata = alerte.get("severity", 3)
            confiance_brute = _confiance_suricata(signature, severite_suricata)

            evenements.append({
                "scenario": scenario,
                "description": signature,
                "confidence_brute": confiance_brute,
                "source": enregistrement.get("src_ip", "inconnue"),
                "origine": "Suricata",
            })

    return evenements


# ---------------------------------------------------------------------------
# WAZUH : correspondance groupe de regle -> scenario du prototype
# ---------------------------------------------------------------------------
# Meme classement que wazuh_temps_reel._classer_wazuh, pour que les
# deux chemins de collecte donnent le meme resultat pour la meme alerte.
# Attention : "root" n'est pas teste seul en sous-chaine, sinon le mot
# "rootcheck" (groupe Wazuh) declencherait a tort un 0,95 critique pour
# toutes les alertes rootcheck. On ne retient que les cas caracterises :
# uid=0, backdoor, sudo, privilege.
def _classer_wazuh(regle, texte_complet=""):
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
            or "authentication_failures" in texte:
        return "bruteforce", min(max(niveau / 15.0, 0.60), 0.99)
    # Integrite de fichiers
    if "syscheck" in texte:
        return "sensitive_file_change", min(max(niveau / 15.0, 0.60), 0.95)
    # Par defaut : confiance derivee du niveau Wazuh, sans plancher.
    return "suspicious_process", round(min(niveau / 15.0, 0.99), 2)


def _scenario_wazuh(groupes):
    """Compatibilite : scenario seul, sans la confiance."""
    scenario, _confiance = _classer_wazuh({"level": 0, "groups": groupes or []})
    return scenario


def lire_evenements_wazuh(chemin=CHEMIN_ALERTS_WAZUH):
    """
    Lit une copie lisible du fichier alerts.json de Wazuh et renvoie la
    liste des evenements (au format du prototype).

    Wazuh note la gravite de ses regles de 0 a 15 (rule.level). On la
    ramene a une confiance brute entre 0 et 1, avec les regles de
    _classer_wazuh (voir ci-dessus).
    """
    evenements = []
    if not os.path.exists(chemin):
        return evenements

    with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                enregistrement = json.loads(ligne)
            except json.JSONDecodeError:
                continue

            regle = enregistrement.get("rule", {})
            niveau = regle.get("level", 0)
            # On ignore le bruit de fond (regles de tres bas niveau).
            if niveau < 3:
                continue

            scenario, confiance_brute = _classer_wazuh(
                regle, enregistrement.get("full_log", ""))

            donnees = enregistrement.get("data", {})
            source = donnees.get("srcip") \
                or enregistrement.get("agent", {}).get("name", "hote-local")

            evenements.append({
                "scenario": scenario,
                "description": regle.get("description", "Alerte Wazuh"),
                "confidence_brute": confiance_brute,
                "source": source,
                "origine": "Wazuh",
            })

    return evenements


def lire_tous_les_evenements(chemin_suricata=CHEMIN_EVE_SURICATA,
                             chemin_wazuh=CHEMIN_ALERTS_WAZUH):
    """Reunit les evenements des deux sources en une seule liste."""
    return lire_evenements_suricata(chemin_suricata) + lire_evenements_wazuh(chemin_wazuh)


if __name__ == "__main__":
    evts = lire_tous_les_evenements()
    print(f"{len(evts)} evenement(s) reel(s) collecte(s).")
    for e in evts[:10]:
        print(e)
