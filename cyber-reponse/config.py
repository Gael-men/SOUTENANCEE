"""
Configuration centrale du prototype.

Regroupe les seuils de decision, les niveaux de severite et la table
des actions reversibles, pour que tout le reste du code (detection,
decision, reponse, tableau de bord) se base sur les memes regles.
"""

# Seuil de confiance a partir duquel une reponse automatique est declenchee
SEUIL_CONFIANCE_AUTO = 0.90

# Niveaux de severite possibles, du plus faible au plus critique
NIVEAUX_SEVERITE = ["faible", "moyenne", "elevee", "critique"]

# Actions reversibles : action -> action inverse.
# Une action absente de ce dictionnaire est consideree comme non reversible
# (ex: "stop_process" ne peut pas etre annule automatiquement).
ACTIONS_REVERSIBLES = {
    "block_source": "unblock_source",
}

# Libelles simples, sans jargon technique, pour l'affichage dans le
# tableau de bord destine a un personnel IT non specialise.
LIBELLES_STATUT = {
    "NEW": "Nouveau",
    "CONFIRMED": "Confirme",
    "FALSE_POSITIVE": "Fausse alerte",
    "RESOLVED": "Resolu",
}

LIBELLES_SEVERITE = {
    "faible": "Faible",
    "moyenne": "Moyenne",
    "elevee": "Elevee",
    "critique": "Critique",
}

DB_NAME = "cyber_response.db"
