"""
Moteur de reponse (module M4).

Execute les actions de reponse (simulees) et leurs contre-actions
eventuelles, pour les actions reversibles (voir config.py).
"""


def execute(action, source=None):
    """Execute (simule) une action de reponse."""
    if action == "block_source":
        return f"SIMULATION : blocage de la source {source}"

    if action == "stop_process":
        return "SIMULATION : arret du processus suspect"

    if action == "notify_admin":
        return "ALERTE : intervention de l'administrateur requise"

    return "ACTION INCONNUE"


def reverse(action, source=None):
    """Execute (simule) la contre-action d'une action reversible."""
    if action == "block_source":
        return f"SIMULATION : deblocage de la source {source}"

    return "AUCUNE CONTRE-ACTION DISPONIBLE POUR CETTE ACTION"


if __name__ == "__main__":
    print(execute("block_source", "192.168.1.50"))
    print(reverse("block_source", "192.168.1.50"))
