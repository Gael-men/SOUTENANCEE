"""
Conseils et explications en langage clair (module d'aide a la decision).

Pour chaque incident, la plateforme ne se contente pas d'afficher une
gravite : elle explique, dans un francais simple et sans jargon, ce qui
s'est passe, ce qu'elle a fait automatiquement, et ce que l'operateur IT
(non specialiste) devrait faire. C'est ce qui rend l'outil utilisable par
un personnel generaliste de PME.
"""

EXPLICATIONS = {
    "bruteforce": (
        "Plusieurs tentatives de connexion repetees ont ete detectees "
        "depuis la meme source. C'est le signe typique d'une attaque par "
        "force brute (un attaquant qui essaie de deviner un mot de passe). "
        "Plus rarement, cela peut etre un utilisateur legitime qui a oublie "
        "son mot de passe."
    ),
    "suspicious_process": (
        "Une activite inhabituelle a ete detectee sur le reseau ou le "
        "systeme (trafic ou processus suspect). Ce type d'activite accompagne "
        "souvent la reconnaissance d'une cible ou une tentative d'intrusion."
    ),
    "sensitive_file_change": (
        "Un fichier sensible surveille a ete modifie. Une modification non "
        "prevue peut indiquer qu'un attaquant ou un logiciel malveillant a "
        "altere un fichier important."
    ),
}


def expliquer(scenario, decision, action, reversible, severite):
    """Renvoie (ce_qui_s_est_passe, ce_que_la_plateforme_a_fait,
    ce_que_vous_devez_faire, priorite)."""

    quoi = EXPLICATIONS.get(
        scenario, "Une activite de securite a ete detectee sur le systeme.")

    if decision == "respond" and action == "block_source":
        fait = ("La plateforme a BLOQUE automatiquement la source de l'attaque "
                "pour l'arreter immediatement. Cette action est REVERSIBLE : "
                "si c'etait une erreur, vous pouvez la defaire avec le bouton "
                "\"Annuler l'action\".")
    elif decision == "respond" and action == "stop_process":
        fait = ("La plateforme a ARRETE automatiquement le processus suspect. "
                "Attention : cette action n'est PAS reversible.")
    else:
        fait = ("La plateforme n'a pris aucune action automatique : elle vous "
                "SIGNALE l'incident pour que vous decidiez de la suite "
                "(verification humaine).")

    if scenario == "bruteforce":
        reco = ("Verifiez si la source correspond a un utilisateur connu de "
                "l'entreprise. Si OUI (ex: un employe qui a oublie son mot de "
                "passe), annulez le blocage et aidez-le a reinitialiser son mot "
                "de passe. Si NON, laissez le blocage et cliquez sur "
                "\"Confirmer\".")
    elif scenario == "suspicious_process":
        reco = ("Identifiez le programme ou la machine a l'origine de "
                "l'activite. Si c'est legitime, marquez \"Fausse alerte\". "
                "Sinon, cliquez sur \"Confirmer\" et lancez une analyse "
                "antivirus sur la machine concernee.")
    elif scenario == "sensitive_file_change":
        reco = ("Verifiez qui a modifie le fichier et si la modification etait "
                "prevue. Si non, restaurez une version saine depuis une "
                "sauvegarde, puis cliquez sur \"Confirmer\".")
    else:
        reco = ("Verifiez l'activite signalee, puis cliquez sur \"Confirmer\" "
                "ou \"Fausse alerte\".")

    if severite == "critique":
        priorite = "Priorite : A TRAITER IMMEDIATEMENT."
    elif severite == "elevee":
        priorite = "Priorite : a traiter rapidement."
    elif severite == "moyenne":
        priorite = "Priorite : a verifier dans la journee."
    else:
        priorite = "Priorite : surveillance, risque faible."

    return quoi, fait, reco, priorite
