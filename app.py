import streamlit as st
import os
import tempfile
import pandas as pd
import plotly.express as px
from analyseur import parse_email, evaluate_phishing_score, analyze_urls_virustotal

st.set_page_config(page_title="Dashboard Phishing", page_icon="🎣", layout="wide")

st.title("🎣 Analyseur de Phishing - Dashboard")
st.markdown("Glissez-déposez votre fichier `.eml` ci-dessous pour lancer l'analyse complète.")

api_key = st.text_input("Clé API VirusTotal (Optionnel)", type="password", help="Permet d'analyser les liens trouvés avec VirusTotal.")
uploaded_file = st.file_uploader("Choisissez un fichier .eml", type=["eml"])

if uploaded_file is not None:
    # Save the file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as get_temp:
        get_temp.write(uploaded_file.getvalue())
        temp_path = get_temp.name

    try:
        with st.spinner("Analyse de l'email en cours..."):
            sender, urls_trouvees, all_text = parse_email(temp_path)
            
            vt_results = None
            if api_key and urls_trouvees:
                st.info(f"Analyse de {len(urls_trouvees)} URL(s) avec VirusTotal... (cela peut prendre du temps)")
                vt_results = analyze_urls_virustotal(urls_trouvees, api_key)
                
            score, details, kws = evaluate_phishing_score(sender, all_text, urls_trouvees, vt_results)

        st.success("Analyse terminée !")
        
        # Dashboard layout
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.subheader("Score de Risque")
            # Affichage en metric
            if score >= 70:
                st.metric(label="Score de Menace (Max: 100)", value=f"{score} 🔴", delta="Risque Critique", delta_color="inverse")
                st.error("**TRÈS PROBABLEMENT UN PHISHING.** Ne cliquez sur aucun lien et supprimez ce mail.")
            elif score >= 40:
                st.metric(label="Score de Menace (Max: 100)", value=f"{score} 🟠", delta="Suspect", delta_color="off")
                st.warning("**SUSPECT.** Soyez prudent, ce mail présente plusieurs caractéristiques de phishing.")
            else:
                st.metric(label="Score de Menace (Max: 100)", value=f"{score} 🟢", delta="Faible Risque", delta_color="normal")
                st.success("**FAIBLE RISQUE.** Ce mail semble légitime, mais restez vigilant.")
                
            st.markdown("### Expéditeur")
            st.write(f"**{sender}**")
            
        with col2:
            st.subheader("Détails de l'Analyse")
            for detail in details:
                if detail.startswith("[!]"):
                    st.error(detail)
                elif detail.startswith("[+]"):
                    st.info(detail)
                else:
                    st.write(detail)

        st.markdown("---")
        
        # Mots-Clés Proportion (Pie Chart) & Liens
        col3, col4 = st.columns(2)
        with col3:
            st.subheader("Proportion de Mots-Clés d'Urgence")
            if kws:
                df_kws = pd.DataFrame(list(kws.items()), columns=['Mot-Clé', 'Occurrences'])
                fig = px.pie(df_kws, values='Occurrences', names='Mot-Clé', 
                             title="Mots-Clés Détectés", hole=0.4,
                             color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Aucun mot-clé d'urgence détecté dans le corps du texte.")
                
        with col4:
            st.subheader("Liens Trouvés")
            if urls_trouvees:
                for u in sorted(urls_trouvees):
                    st.code(u)
            else:
                st.info("Aucun lien détecté dans ce mail.")

    finally:
        # Nettoyage
        if os.path.exists(temp_path):
            os.remove(temp_path)
