"""
Module d'authentification (controle d'acces au tableau de bord).

Le mot de passe n'est jamais stocke en clair : seule son empreinte
SHA-256 est conservee.

Modele de gestion des comptes : PROVISIONNEMENT PAR L'ADMINISTRATEUR.
Il n'y a pas d'auto-inscription (choix de securite volontaire : sur un
outil de supervision de securite, autoriser n'importe qui a creer un
compte serait une faille). L'administrateur ajoute les utilisateurs
avec l'outil ajouter_utilisateur.py, qui les enregistre dans le fichier
utilisateurs.json.

--------------------------------------------------------------------
COMPTE ADMINISTRATEUR PAR DEFAUT :
    Identifiant  : admin
    Mot de passe : esgis2026
--------------------------------------------------------------------
"""

import hashlib
import json
import os

CHEMIN_UTILISATEURS = "utilisateurs.json"

# Compte administrateur par defaut, toujours disponible meme si le
# fichier utilisateurs.json n'existe pas encore.
_DEFAUT = {
    "admin": {
        "mot_de_passe_hash": "92611f1b828e5fc1e0991614350aed098d08a3937c111b4234d50b15bb54e49b",
        "nom_affiche": "Gael",
    },
}


def _charger_utilisateurs():
    """Comptes par defaut, completes par ceux crees par l'administrateur."""
    utilisateurs = dict(_DEFAUT)
    if os.path.exists(CHEMIN_UTILISATEURS):
        try:
            with open(CHEMIN_UTILISATEURS, encoding="utf-8") as fichier:
                utilisateurs.update(json.load(fichier))
        except (json.JSONDecodeError, OSError):
            pass
    return utilisateurs


def verifier(identifiant, mot_de_passe):
    """Renvoie le nom affiche si les identifiants sont corrects, sinon None."""
    utilisateur = _charger_utilisateurs().get((identifiant or "").strip())
    if not utilisateur:
        return None
    empreinte = hashlib.sha256((mot_de_passe or "").encode()).hexdigest()
    if empreinte == utilisateur["mot_de_passe_hash"]:
        return utilisateur["nom_affiche"]
    return None
