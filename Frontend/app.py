import streamlit as st
import requests
import pandas as pd
import json

st.set_page_config(page_title="TLSAssistant Flow", layout="wide")
st.title("🛡️ TLSAssistant - SBOM Analyzer")

BACKEND_URL = "http://127.0.0.1:8000"

# Stato di Streamlit per ricordarsi se la Fase 1 è completata
if "sbom_ready" not in st.session_state:
    st.session_state.sbom_ready = False

# ============================================================
# STEP 1 & 2: REPO E ACQUISIZIONE SBOM (SALVATAGGIO SERVER)
# ============================================================
st.subheader("1. Configurazione Target & SBOM di Base")
repo_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/owner/repo")
branch = st.text_input("Branch", value="main")

sbom_choice = st.radio(
    "Scegli l'origine dello SBOM di base:",
    ["Genera SBOM Statico da zero", "Carica file SBOM esistenti"],
    horizontal=True
)

requirements_file = None
poetry_file = None
format_file = "entrambi" # Default value

if sbom_choice == "Carica file SBOM esistenti":
    col1, col2 = st.columns(2)
    with col1:
        requirements_file = st.file_uploader("Carica JSON Requirements", type=["json"])
    with col2:
        poetry_file = st.file_uploader("Carica JSON Poetry", type=["json"])
elif sbom_choice == "Genera SBOM Statico da zero":
    format_type = st.selectbox(
        "Seleziona il formato da generare tramite la pipeline:",
        options=["entrambi", "requirements", "poetry"],
        format_func=lambda x: x.capitalize()
    )
    format_file = format_type

if st.button("🔄 Invia e Mantieni in Memoria sul Server"):
    if not repo_url:
        st.error("Inserisci la URL della repo.")
        st.stop()
        
    with st.spinner("Salvataggio file sul server..."):
        try:
            if sbom_choice == "Genera SBOM Statico da zero":
                res = requests.post(f"{BACKEND_URL}/upload-sbom", data={"action": "generate"})
            else:
                files = {}
                if requirements_file: files["requirements_file"] = requirements_file.getvalue()
                if poetry_file: files["poetry_file"] = poetry_file.getvalue()
                res = requests.post(f"{BACKEND_URL}/upload-sbom", data={"action": "upload", "format": format_file}, files=files)
                
            if res.status_code == 200:
                st.session_state.sbom_ready = True
                st.success(res.json().get("message"))
            else:
                st.error(f"Errore server: {res.text}")
        except Exception as e:
            st.error(f"Errore di connessione: {str(e)}")

st.markdown("---")

# ============================================================
# STEP 3 & 4: INPUT DINAMICO E TABELLA DI CONFRONTO
# ============================================================
if st.session_state.sbom_ready:
    st.subheader("2. Analisi Comparativa Dinamica")
    
    path_dipendenze = st.text_input(
        "Nome del file delle dipendenze dinamiche nella repo:",
        value="dependencies.json"
    ).strip()
    
    if st.button("📊 Genera Tabella di Confronto Finale"):
        with st.spinner("Clonazione repo e calcolo matrice in corso..."):
            try:
                res = requests.post(
                    f"{BACKEND_URL}/compare-dependencies",
                    params={
                        "repo_url": repo_url,
                        "branch": branch,
                        "path_dipendenze": path_dipendenze,
                    },
                )

                if res.status_code == 200:
                    result = res.json()
                    dependencies = result.get("result", [])
                    git_repos = [
                        item["url"]
                        for item in dependencies
                        if item.get("url") and "github.com" in item["url"]
                    ]
                    comparison_report = result.get("comparison_matrix", None)

                    st.subheader("📊 Risultati dell'Analisi")

                    tab_labels = [
                        f"📦 Componenti Rilevati ({len(dependencies)})",
                        "🔗 Link GitHub Sorgenti",
                    ]
                    if comparison_report:
                        tab_labels.append("🔍 Matrice di Confronto (Pipeline)")
                    tab_labels.append("📄 JSON Grezzo Export")

                    tabs = st.tabs(tab_labels)

                    with tabs[0]:
                        if dependencies:
                            df = pd.DataFrame(dependencies)
                            cols_desiderate = [
                                "type",
                                "name",
                                "url",
                                "present_in_requirements",
                                "present_in_poetry",
                            ]
                            available_cols = [
                                c for c in cols_desiderate if c in df.columns
                            ]
                            df = df[available_cols]

                            df = df.rename(
                                columns={
                                    "type": "Tipo",
                                    "name": "Componente",
                                    "url": "Sorgente / PURL",
                                    "present_in_requirements": "Presente in Requirements",
                                    "present_in_poetry": "Presente in Poetry",
                                }
                            )

                            st.dataframe(df, use_container_width=True)
                            st.download_button(
                                "⬇️ Scarica Elenco Componenti (JSON)",
                                json.dumps(dependencies, indent=2),
                                "dependencies_extracted.json",
                                "application/json",
                            )
                        else:
                            st.info(
                                "Nessuna lista componenti strutturata disponibile."
                            )

                    with tabs[1]:
                        if git_repos:
                            st.markdown(
                                "### Repository esterne associate alle dipendenze:"
                            )
                            for r in sorted(list(set(git_repos))):
                                if r.startswith("http"):
                                    st.markdown(f"- [{r}]({r})")
                                else:
                                    st.markdown(f"- {r}")
                        else:
                            st.info(
                                "Nessuna repository GitHub mappata come dipendenza diretta."
                            )

                    current_tab_idx = 2
                    if comparison_report:
                        with tabs[2]:
                            st.markdown(
                                "### Output di Divergenza Generato dagli Script"
                            )
                            if result.get("github_run_url"):
                                st.markdown(
                                    f"🌐 [Link alla Run di GitHub Actions]({result.get('github_run_url')})"
                                )
                            st.text_area(
                                "Log di Confronto:",
                                value=comparison_report,
                                height=400,
                            )
                        current_tab_idx = 3

                    with tabs[current_tab_idx]:
                        st.code(json.dumps(result, indent=2), language="json")
                        st.download_button(
                            "⬇️ Scarica Output SBOM Finale",
                            json.dumps(result, indent=2),
                            "sbom_full_output.json",
                            "application/json",
                        )
                else:
                    st.error(f"Errore: {res.text}")
            except Exception as e:
                st.error(f"Errore durante l'elaborazione: {str(e)}")
else:
    st.warning(
        "⚠️ Completa il punto precedente e clicca su 'Invia e Mantieni in Memoria sul Server' per sbloccare l'analisi."
    )