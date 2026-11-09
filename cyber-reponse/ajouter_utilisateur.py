"""
Outil d'administration des comptes du tableau de bord.

Permet a l'administrateur de :
  - creer un nouvel utilisateur ;
  - OU mettre a jour un utilisateur existant : changer le NOM AFFICHE
    sur le tableau de bord (la salutation "Bonjour, ..."), et/ou le mot
    de passe.

Usage (dans le dossier du projet) :
    python ajouter_utilisateur.py

Le mot de passe est saisi de facon masquee et stocke uniquement sous
forme d'empreinte SHA-256. Le mot de passe en clair n'est jamais ecrit.
"""

import hashlib
import json
import os
import getpass

from auth import CHEMIN_UTILISATEURS, _DEFAUT


def charger():
    utilisateurs = {}
    if os.path.exists(CHEMIN_UTILISATEURS):
        try:
            with open(CHEMIN_UTILISATEURS, encoding="utf-8") as fichier:
                utilisateurs = json.load(fichier)
        except (json.JSONDecodeError, OSError):
            utilisateurs = {}
    return utilisateurs


def main():
    utilisateurs = charger()
    # Comptes connus = ceux du fichier + le compte admin par defaut.
    comptes_connus = set(utilisateurs) | set(_DEFAUT)

    identifiant = input("Identifiant de l'utilisateur : ").strip()
    if not identifiant:
        print("Identifiant obligatoire. Abandon.")
        return

    existe = identifiant in comptes_connus
    if existe:
        print(f"-> Utilisateur '{identifiant}' existant : mise a jour.")
        nom = input("Nouveau nom affiche sur le dashboard "
                    "(laisser vide pour ne pas changer) : ").strip()
        mot_de_passe = getpass.getpass(
            "Nouveau mot de passe (laisser vide pour ne pas changer) : ")
    else:
        print(f"-> Nouvel utilisateur '{identifiant}'.")
        nom = input("Nom affiche sur le dashboard : ").strip()
        mot_de_passe = getpass.getpass("Mot de passe : ")
        confirmation = getpass.getpass("Confirmer le mot de passe : ")
        if not mot_de_passe:
            print("Mot de passe obligatoire pour un nouvel utilisateur. Abandon.")
            return
        if mot_de_passe != confirmation:
            print("Les deux mots de passe ne correspondent pas. Abandon.")
            return

    # Point de depart : l'entree existante (fichier, ou valeur par defaut).
    entree = dict(utilisateurs.get(identifiant) or _DEFAUT.get(identifiant) or {})

    if nom:
        entree["nom_affiche"] = nom
    elif "nom_affiche" not in entree:
        entree["nom_affiche"] = identifiant

    if mot_de_passe:
        entree["mot_de_passe_hash"] = hashlib.sha256(mot_de_passe.encode()).hexdigest()
    if "mot_de_passe_hash" not in entree:
        print("Aucun mot de passe defini pour ce compte. Abandon.")
        return

    utilisateurs[identifiant] = entree
    with open(CHEMIN_UTILISATEURS, "w", encoding="utf-8") as fichier:
        json.dump(utilisateurs, fichier, indent=2, ensure_ascii=False)

    print(f"Compte '{identifiant}' enregistre. "
          f"Nom affiche : {entree['nom_affiche']}")


if __name__ == "__main__":
    main()
