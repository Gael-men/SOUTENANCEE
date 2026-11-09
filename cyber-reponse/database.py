"""
Persistance des incidents (support du module M5 / Base de donnees).

init_db() cree la table si besoin et ajoute les colonnes manquantes
(migration simple). Les incidents de meme nature (meme scenario, meme
description, meme source) qui sont encore actifs sont REGROUPES : au lieu
de creer une ligne par evenement, on incremente un compteur d'occurrences.
Cela evite d'encombrer le tableau de bord et de saturer la base lors d'une
attaque qui genere beaucoup d'evenements (ex: un brute-force).
"""

import sqlite3
from config import DB_NAME

COLONNES_ATTENDUES = {
    "description": "TEXT",
    "severite": "TEXT",
    "reversible": "INTEGER",
    "statut": "TEXT",
    "action_statut": "TEXT",
    "reviewed_at": "TEXT",
    "occurrences": "INTEGER",
    "derniere_fois": "TEXT",
}


def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT NOT NULL,
            confidence REAL,
            decision TEXT,
            action TEXT,
            source TEXT,
            reason TEXT,
            created_at TEXT
        )
    """)
    colonnes_existantes = {ligne[1] for ligne in conn.execute("PRAGMA table_info(incidents)")}
    for colonne, type_sql in COLONNES_ATTENDUES.items():
        if colonne not in colonnes_existantes:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {colonne} {type_sql}")
    conn.commit()
    conn.close()


def save_incident(incident):
    """Enregistre un nouvel incident et renvoie son id."""
    conn = sqlite3.connect(DB_NAME)
    cur = conn.execute("""
        INSERT INTO incidents
        (scenario, description, confidence, severite, decision, action,
         source, reason, reversible, statut, action_statut, created_at,
         reviewed_at, occurrences, derniere_fois)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident.get("scenario"),
        incident.get("description"),
        incident.get("confidence"),
        incident.get("severite"),
        incident.get("decision"),
        incident.get("action"),
        incident.get("source"),
        incident.get("reason"),
        1 if incident.get("reversible") else 0,
        incident.get("statut"),
        incident.get("action_statut"),
        incident.get("created_at"),
        incident.get("reviewed_at"),
        incident.get("occurrences", 1),
        incident.get("derniere_fois", incident.get("created_at")),
    ))
    conn.commit()
    incident_id = cur.lastrowid
    conn.close()
    return incident_id


def trouver_incident_actif(scenario, description, source):
    """
    Cherche un incident encore actif (statut Nouveau ou Confirme) de meme
    nature. Renvoie (id, occurrences) si trouve, sinon None.
    """
    conn = sqlite3.connect(DB_NAME)
    ligne = conn.execute(
        "SELECT id, occurrences FROM incidents "
        "WHERE scenario = ? AND description = ? AND source = ? "
        "AND statut IN ('NEW', 'CONFIRMED') "
        "ORDER BY id DESC LIMIT 1",
        (scenario, description, source),
    ).fetchone()
    conn.close()
    return ligne


def incrementer_occurrence(incident_id, derniere_fois):
    """Incremente le compteur d'un incident existant et met a jour l'heure."""
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        "UPDATE incidents SET occurrences = COALESCE(occurrences, 1) + 1, "
        "derniere_fois = ? WHERE id = ?",
        (derniere_fois, incident_id),
    )
    conn.commit()
    conn.close()


def update_incident_statut(incident_id, statut=None, action_statut=None, reviewed_at=None):
    conn = sqlite3.connect(DB_NAME)
    if statut is not None:
        conn.execute("UPDATE incidents SET statut = ? WHERE id = ?", (statut, incident_id))
    if action_statut is not None:
        conn.execute("UPDATE incidents SET action_statut = ? WHERE id = ?", (action_statut, incident_id))
    if reviewed_at is not None:
        conn.execute("UPDATE incidents SET reviewed_at = ? WHERE id = ?", (reviewed_at, incident_id))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Base de donnees initialisee / migree.")
