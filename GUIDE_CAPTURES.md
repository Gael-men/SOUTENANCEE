# GUIDE COMPLET — LANCER LA DÉMO ET FAIRE LES CAPTURES

Projet : C:\Users\Mr-G\Documents\1MEMOIRESI 2026\cyber-reponse
Identifiants du tableau de bord : identifiant = admin , mot de passe = esgis2026
Pour capturer : touche Windows + Maj + S, sélectionne la zone (elle est copiée), puis Ctrl + V dans Word sur le bandeau jaune de la figure.

====================================================================
PARTIE 1 — LANCER LES 5 FENÊTRES (le "décor")
====================================================================

----- FENÊTRE 1 : WAZUH (surveillance des machines) -----
Ouvre l'application "Ubuntu". Tape :

   sudo /var/ossec/bin/wazuh-control start
   sudo /var/ossec/bin/wazuh-control status

Tu dois voir plusieurs lignes "is running". Laisse cette fenêtre ouverte.

----- FENÊTRE 2 : SURICATA (surveillance du réseau) -----
Ouvre PowerShell EN ADMINISTRATEUR (clic droit > Exécuter en tant qu'administrateur). Tape :

   cd "C:\Program Files\Suricata"
   .\suricata.exe -c suricata.yaml -i "\Device\NPF_{36F44141-0857-4B2E-B0A2-E900654428CF}"

Suricata démarre et écoute. Laisse tourner (ne ferme pas).

----- FENÊTRE 3 : LE COLLECTEUR (temps réel) -----
Ouvre une nouvelle fenêtre PowerShell (normale). Tape :

   cd "C:\Users\Mr-G\Documents\1MEMOIRESI 2026\cyber-reponse"
   ..\.venv\Scripts\Activate.ps1
   python demo_attaque.py reset
   python collecteur_continu.py

Le collecteur tourne en boucle (il lit les alertes). Laisse tourner.

----- FENÊTRE 4 : LE TABLEAU DE BORD -----
Ouvre une nouvelle fenêtre PowerShell. Tape :

   cd "C:\Users\Mr-G\Documents\1MEMOIRESI 2026\cyber-reponse"
   ..\.venv\Scripts\Activate.ps1
   python -m streamlit run app.py

Ça ouvre le navigateur sur http://localhost:8501
Connecte-toi : identifiant = admin , mot de passe = esgis2026
Dans la barre latérale, COCHE la case "Actualisation automatique".
IMPORTANT : ne recharge JAMAIS la page à la main (ça déconnecte). Le temps réel met tout à jour tout seul.

----- FENÊTRE 5 : LES ATTAQUES -----
Ouvre une dernière fenêtre PowerShell. Tape :

   cd "C:\Users\Mr-G\Documents\1MEMOIRESI 2026\cyber-reponse"
   ..\.venv\Scripts\Activate.ps1

Cette fenêtre servira à lancer les attaques réseau.

====================================================================
CAPTURE >>> FIGURE 5 : ENVIRONNEMENT DE MISE EN ŒUVRE
====================================================================
Quand les 5 fenêtres tournent, place côte à côte les fenêtres Suricata (2),
Collecteur (3) et Ubuntu/Wazuh (1), et fais une capture d'ensemble.
=> C'est la FIGURE 5.

====================================================================
PARTIE 2 — LES ATTAQUES (une par une) + CAPTURES
====================================================================
Après chaque attaque, attends 3 à 5 secondes et regarde le tableau de bord :
l'incident apparaît tout seul.

--- ATTAQUE 1 : PING (reconnaissance réseau) — gravité FAIBLE ---
Dans la FENÊTRE 5, tape :
   ping -n 20 8.8.8.8
Résultat attendu : un incident de gravité faible sur le dashboard.

--- ATTAQUE 2 : FORCE BRUTE (réseau) — gravité CRITIQUE, réponse auto réversible ---
Dans la FENÊTRE 5, tape :
   1..3 | ForEach-Object { Test-NetConnection -ComputerName 8.8.8.8 -Port 23 -InformationLevel Quiet }
Résultat attendu : un incident CRITIQUE (rouge) avec une réponse automatique réversible
et un bouton "Annuler l'action".

>>> CAPTURE FIGURE 4 : clique sur cet incident critique pour le DÉPLIER
(on doit voir : la gravité critique, "réponse automatique", et le bouton "Annuler l'action").
=> C'est la FIGURE 4.

--- ATTAQUE 3 : SCAN DE PORTS — gravité ÉLEVÉE, alerte humaine ---
Dans la FENÊTRE 5, tape :
   1..60 | ForEach-Object { $c = New-Object System.Net.Sockets.TcpClient; $c.BeginConnect("8.8.8.8", $_, $null, $null) | Out-Null; Start-Sleep -Milliseconds 40; $c.Close() }
Résultat attendu : un incident de gravité élevée transmis en alerte (vérification humaine).

--- ATTAQUE 4 : ÉCHECS D'AUTHENTIFICATION (hôte, Wazuh) ---
Dans la FENÊTRE 1 (Ubuntu), tape :
   for i in $(seq 5); do echo mauvais | sudo -S -k true 2>/dev/null; done
Résultat attendu : un incident d'authentification remonté par Wazuh.

--- ATTAQUE 5 : ÉLÉVATION DE PRIVILÈGES (hôte, Wazuh) ---
Dans la FENÊTRE 1 (Ubuntu), tape :
   sudo useradd pirate && sudo usermod -aG sudo pirate
Résultat attendu : un incident de privilèges remonté par Wazuh.

--- ATTAQUE 6 : BACKDOOR ROOT (hôte, Wazuh) — gravité CRITIQUE ---
Dans la FENÊTRE 1 (Ubuntu), tape :
   sudo useradd -o -u 0 -g 0 backdoor
Résultat attendu : un incident CRITIQUE (compte caché avec pouvoirs root).
IMPORTANT : vérifie bien que cet incident apparaît. Si rien ne remonte au bout
d'une minute, c'est que Wazuh ne détecte pas ce cas chez toi : dans ce cas,
n'utilise pas la backdoor comme scénario (on reviendra à 8 scénarios).

====================================================================
CAPTURE >>> FIGURE 3 : TABLEAU DE BORD (vue d'ensemble)
====================================================================
Après avoir lancé plusieurs attaques, capture la LISTE complète des incidents
(vue d'ensemble du tableau de bord, sans rien déplier).
=> C'est la FIGURE 3.

====================================================================
CAPTURE >>> FIGURE 6 : RÉSULTAT D'UN SCÉNARIO DE TEST
====================================================================
Déplie un incident (par exemple le ping ou le scan) pour montrer le détail :
gravité, explication en langage clair, et recommandation.
=> C'est la FIGURE 6.

====================================================================
PARTIE 3 — MONTRER LA RÉVERSIBILITÉ (pour la soutenance)
====================================================================
Sur l'incident critique de force brute (Figure 4), le bouton "Annuler l'action"
permet d'annuler la réponse automatique. Tu peux le cliquer pour montrer que
l'action est réversible (utile si le jury demande une démo en direct).

====================================================================
RAPPEL — INSÉRER UNE CAPTURE DANS LE MÉMOIRE (Word)
====================================================================
1. Windows + Maj + S, sélectionne la zone (copiée automatiquement).
2. Dans Word, clique sur le bandeau jaune [ CAPTURE À INSÉRER ICI ] de la bonne figure.
3. Supprime le texte du bandeau (sélectionne-le, touche Suppr).
4. Ctrl + V pour coller la capture.
5. Si trop grande, clique dessus et réduis en tirant un coin.
La légende (Figure 3 : ...) est déjà écrite juste en dessous : n'y touche pas.

RÉCAP DES 4 FIGURES À PRODUIRE :
- Figure 3 : vue d'ensemble du tableau de bord (liste des incidents)
- Figure 4 : incident critique (force brute) déplié avec réponse auto + bouton Annuler
- Figure 5 : environnement (fenêtres Suricata + Wazuh + collecteur)
- Figure 6 : un incident déplié montrant gravité + recommandation
