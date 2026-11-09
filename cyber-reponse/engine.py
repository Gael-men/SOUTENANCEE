def decide(alert):
    """
    Analyse une alerte et détermine l'action à effectuer.
    """

    scenario = alert.get("scenario")
    confidence = alert.get("confidence", 0)

    if scenario == "bruteforce" and confidence >= 0.90:
        return {
            "decision": "respond",
            "action": "block_source",
            "reason": "Brute force détecté avec un niveau de confiance élevé"
        }

    if scenario == "suspicious_process" and confidence >= 0.90:
        return {
            "decision": "respond",
            "action": "stop_process",
            "reason": "Processus suspect détecté avec un niveau de confiance élevé"
        }

    if scenario == "sensitive_file_change":
        return {
            "decision": "alert",
            "action": "notify_admin",
            "reason": "Modification d'un fichier sensible détectée"
        }

    return {
        "decision": "alert",
        "action": "notify_admin",
        "reason": "Événement nécessitant une vérification humaine"
    }


# Test simple
if __name__ == "__main__":
    test_alert = {
        "scenario": "bruteforce",
        "confidence": 0.95
    }

    result = decide(test_alert)
    print(result)
