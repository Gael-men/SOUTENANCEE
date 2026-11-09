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
"""

import json
import os

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
# mot-cle (ex: simple ping ICMP, requete DNS) sont considerees comme
# purement informatives et NE generent PAS d'incident.
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
]

# Suricata note la gravite de 1 (la plus elevee) a 3 (la plus faible).
# On la traduit en une confiance brute comparable a celle du simulateur.
CONFIANCE_PAR_SEVERITE_SURICATA = {1: 0.95, 2: 0.80, 3: 0.62}


def _scenario_suricata(signature):
    texte = (signature or "").lower()
    for mot_cle, scenario in MOTS_CLES_SURICATA:
        if mot_cle in texte:
            return scenario
    return None  # alerte informative, ignoree


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
            confiance_brute = CONFIANCE_PAR_SEVERITE_SURICATA.get(severite_suricata, 0.60)

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
def _scenario_wazuh(groupes):
    texte = " ".join(groupes or []).lower()
    if "authentication_fail" in texte or "invalid_login" in texte \
            or "win_authentication_failed" in texte or "authentication_failures" in texte:
        return "bruteforce"
    if "syscheck" in texte:
        return "sensitive_file_change"
    return "suspicious_process"


def lire_evenements_wazuh(chemin=CHEMIN_ALERTS_WAZUH):
    """
    Lit une copie lisible du fichier alerts.json de Wazuh et renvoie la
    liste des evenements (au format du prototype).

    Wazuh note la gravite de ses regles de 0 a 15 (rule.level). On la
    ramene a une confiance brute entre 0 et 1.
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

            groupes = regle.get("groups", [])
            scenario = _scenario_wazuh(groupes)
            confiance_brute = round(min(niveau / 15.0, 0.99), 2)

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
