"""
Tableau de bord (module M7).

Palette et composants inspires d'une reference visuelle fournie par
l'utilisateur (fond creme/jaune pale, cartes arrondies, pastilles
pilule, un panneau sombre pour la legende), tout en gardant les
regles d'accessibilite du skill dataviz : la gravite utilise la
palette de statut reservee (good/warning/serious/critical), et chaque
pastille porte toujours une icone ET un libelle, jamais la couleur
seule.
"""

import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime

from config import DB_NAME, LIBELLES_STATUT, LIBELLES_SEVERITE
from database import update_incident_statut
from response import reverse as executer_contre_action

st.set_page_config(page_title="Cyber Response", layout="wide")

# --- Palette ---
ENCRE_PRIMAIRE = "#0b0b0b"
ENCRE_SECONDAIRE = "#52514e"
ENCRE_MUTED = "#898781"
PANNEAU_SOMBRE = "#1f1d18"
CREME = "#fdf8ee"
JAUNE_PALE = "#fbe9b8"
BLEU_CATEGORIEL = "#2a78d6"
ORANGE_CATEGORIEL = "#eb6834"

SEVERITE_STYLE = {
    "faible":   {"couleur": "#0ca30c"},
    "moyenne":  {"couleur": "#fab219"},
    "elevee":   {"couleur": "#ec835a"},
    "critique": {"couleur": "#d03b3b"},
}
RANG_SEVERITE = {"critique": 0, "elevee": 1, "moyenne": 2, "faible": 3}

STATUT_STYLE = {
    "NEW":            {"couleur": ENCRE_MUTED},
    "CONFIRMED":      {"couleur": ENCRE_SECONDAIRE},
    "FALSE_POSITIVE": {"couleur": ENCRE_MUTED},
    "RESOLVED":       {"couleur": "#0ca30c"},
}

st.markdown(f"""
<style>
.stApp {{
    background: linear-gradient(135deg, #ffffff 0%, {JAUNE_PALE} 100%);
}}
[data-testid="stSidebar"] {{
    background-color: {PANNEAU_SOMBRE};
}}
[data-testid="stSidebar"] * {{
    color: #f0efec !important;
}}
div[data-testid="stVerticalBlockBorderWrapper"] {{
    background-color: #ffffff;
    border-radius: 16px !important;
    border: 1px solid rgba(11,11,11,0.06) !important;
    box-shadow: 0 2px 10px rgba(11,11,11,0.04);
}}
</style>
""", unsafe_allow_html=True)


def pastille_pilule(libelle, couleur, fond_sombre=False):
    texte = couleur
    fond = couleur + "26"
    if fond_sombre:
        texte = "#ffffff"
        fond = couleur + "40"
    return (
        f'<span style="display:inline-flex; align-items:center; '
        f'background-color:{fond}; color:{texte}; '
        f'padding:4px 14px; border-radius:999px; '
        f'font-weight:600; font-size:0.85em;">{libelle}</span>'
    )


def carte_stat(valeur, libelle):
    return f"""
    <div style="background:#ffffff; border-radius:16px; padding:14px 18px;
                box-shadow:0 2px 10px rgba(11,11,11,0.04); text-align:left;">
        <div style="font-size:1.6em; font-weight:700; color:{ENCRE_PRIMAIRE};">{valeur}</div>
        <div style="font-size:0.8em; color:{ENCRE_SECONDAIRE};">{libelle}</div>
    </div>
    """


with st.sidebar:
    st.markdown("### Cyber Response")
    st.caption(
        "Prototype developpe dans le cadre du memoire de licence "
        "professionnelle (ESGIS), detection et reponse automatisee "
        "aux incidents de securite, pensee pour un personnel IT "
        "generaliste de PME."
    )
    st.divider()
    st.markdown("**Legende des gravites**")
    for niveau, style in SEVERITE_STYLE.items():
        st.markdown(
            pastille_pilule(LIBELLES_SEVERITE[niveau], style["couleur"], fond_sombre=True),
            unsafe_allow_html=True,
        )

st.markdown("<h1 style='font-weight:800;'>Bonjour, Gael</h1>", unsafe_allow_html=True)
st.caption("Voici l'etat de ton systeme de detection et reponse aux incidents.")


def charger_incidents():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC", conn)
    conn.close()
    return df


df = charger_incidents()
nb_total = len(df)
nb_auto = int((df["decision"] == "respond").sum()) if nb_total else 0
nb_alert = int((df["decision"] == "alert").sum()) if nb_total else 0
nb_a_verifier = int((df["statut"] == "NEW").sum()) if nb_total else 0
nb_faux = int((df["statut"] == "FALSE_POSITIVE").sum()) if nb_total else 0

colA, colB, colC, colD, colE = st.columns([1, 1, 1, 1, 1.3])
colA.markdown(carte_stat(nb_total, "Incidents"), unsafe_allow_html=True)
colB.markdown(carte_stat(nb_auto, "Reponses auto."), unsafe_allow_html=True)
colC.markdown(carte_stat(nb_a_verifier, "A verifier"), unsafe_allow_html=True)
colD.markdown(carte_stat(nb_faux, "Fausses alertes"), unsafe_allow_html=True)

# Donut "repartition" (inspire de la reference) : automatique vs alerte humaine
if nb_total:
    pct_auto = round(100 * nb_auto / nb_total)
    pct_alert = 100 - pct_auto
    deg = pct_auto * 3.6
    colE.markdown(f"""
    <div style="background:{PANNEAU_SOMBRE}; border-radius:16px; padding:14px;
                text-align:center; color:#f0efec;">
      <div style="font-size:0.78em; margin-bottom:6px;">Repartition</div>
      <div style="width:76px; height:76px; border-radius:50%; margin:0 auto;
                  background:conic-gradient({BLEU_CATEGORIEL} 0deg {deg}deg,
                  {ORANGE_CATEGORIEL} {deg}deg 360deg);
                  display:flex; align-items:center; justify-content:center;">
        <div style="width:50px; height:50px; border-radius:50%; background:{PANNEAU_SOMBRE};
                    display:flex; align-items:center; justify-content:center;
                    font-size:0.75em; font-weight:700;">{nb_total}</div>
      </div>
      <div style="font-size:0.72em; margin-top:8px;">
        <span style="color:{BLEU_CATEGORIEL};">●</span> Auto {pct_auto}%
        &nbsp; <span style="color:{ORANGE_CATEGORIEL};">●</span> Alerte {pct_alert}%
      </div>
    </div>
    """, unsafe_allow_html=True)
else:
    colE.markdown(carte_stat(0, "Repartition"), unsafe_allow_html=True)

st.divider()
st.subheader("Filtrer les incidents")

colf1, colf2 = st.columns(2)
statuts_dispo = ["Tous"] + list(LIBELLES_STATUT.values())
severites_dispo = ["Toutes"] + list(LIBELLES_SEVERITE.values())
statut_choisi = colf1.selectbox("Statut", statuts_dispo)
severite_choisie = colf2.selectbox("Gravite", severites_dispo)

df_filtre = df.copy()
if not df_filtre.empty:
    df_filtre["statut_libelle"] = df_filtre["statut"].map(LIBELLES_STATUT).fillna(df_filtre["statut"])
    df_filtre["severite_libelle"] = df_filtre["severite"].map(LIBELLES_SEVERITE).fillna(df_filtre["severite"])
    df_filtre["rang_severite"] = df_filtre["severite"].map(RANG_SEVERITE).fillna(99)

    if statut_choisi != "Tous":
        df_filtre = df_filtre[df_filtre["statut_libelle"] == statut_choisi]
    if severite_choisie != "Toutes":
        df_filtre = df_filtre[df_filtre["severite_libelle"] == severite_choisie]

    df_filtre = df_filtre.sort_values(["rang_severite", "id"], ascending=[True, False])

st.divider()
st.subheader("Incidents detectes")
st.caption("Tries par gravite : les cas les plus critiques apparaissent en premier.")

if df_filtre.empty:
    st.info("Aucun incident ne correspond aux filtres choisis.")
else:
    for _, ligne in df_filtre.iterrows():
        sev_style = SEVERITE_STYLE.get(ligne["severite"], SEVERITE_STYLE["faible"])
        stat_style = STATUT_STYLE.get(ligne["statut"], STATUT_STYLE["NEW"])
        severite_libelle = LIBELLES_SEVERITE.get(ligne["severite"], ligne["severite"])
        statut_libelle = LIBELLES_STATUT.get(ligne["statut"], ligne["statut"])

        with st.container(border=True):
            c1, c2, c3 = st.columns([3, 1, 1])
            c1.markdown(f"**{ligne['description']}** (source {ligne['source']})")
            c1.caption(f"Confiance : {ligne['confidence']}  |  {ligne['reason']}")
            c2.markdown(pastille_pilule(severite_libelle, sev_style["couleur"]),
                        unsafe_allow_html=True)
            c3.markdown(pastille_pilule(statut_libelle, stat_style["couleur"]),
                        unsafe_allow_html=True)

            b1, b2, b3, b4 = st.columns(4)

            if ligne["statut"] == "NEW":
                if b1.button("Confirmer", key=f"conf_{ligne['id']}"):
                    update_incident_statut(int(ligne["id"]), statut="CONFIRMED",
                                            reviewed_at=datetime.now().isoformat())
                    st.rerun()
                if b2.button("Fausse alerte", key=f"fp_{ligne['id']}"):
                    update_incident_statut(int(ligne["id"]), statut="FALSE_POSITIVE",
                                            reviewed_at=datetime.now().isoformat())
                    st.rerun()

            if ligne["statut"] in ("NEW", "CONFIRMED"):
                if b3.button("Marquer resolu", key=f"res_{ligne['id']}"):
                    update_incident_statut(int(ligne["id"]), statut="RESOLVED",
                                            reviewed_at=datetime.now().isoformat())
                    st.rerun()

            if ligne["reversible"] and ligne["action_statut"] == "APPLIED":
                if b4.button("Annuler l'action", key=f"rev_{ligne['id']}"):
                    executer_contre_action(ligne["action"], ligne["source"])
                    update_incident_statut(int(ligne["id"]), action_statut="REVERSED",
                                            reviewed_at=datetime.now().isoformat())
                    st.rerun()
            elif ligne["action_statut"] == "REVERSED":
                b4.caption("Action annulee")
