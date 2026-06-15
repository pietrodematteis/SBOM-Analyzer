import streamlit as st
import requests
import pandas as pd
import json

st.set_page_config(
    page_title="TLSAssistant SBOM Analyzer",
    layout="wide"
)

st.title("TLSAssistant - SBOM & Dependency Analyzer")

BACKEND_URL = "http://127.0.0.1:8000"

# ============================================================
# MODE
# ============================================================

mode = st.radio(
    "Modalità input",
    ["Upload dependency.json", "GitHub Repository"]
)

uploaded_file = None
repo_url = None
branch = "main"

if mode == "Upload dependency.json":

    uploaded_file = st.file_uploader(
        "Carica dependency.json",
        type=["json"]
    )

else:

    repo_url = st.text_input(
        "GitHub Repository URL"
    )

    branch = st.text_input(
        "Branch",
        value="main"
    )

# ============================================================
# RUN
# ============================================================

if st.button("Avvia Analisi"):

    with st.spinner("Analisi in corso..."):

        try:

            # =========================
            # FILE MODE
            # =========================
            if uploaded_file is not None:

                response = requests.post(
                    BACKEND_URL + "/analyze",
                    files={
                        "file": (
                            uploaded_file.name,
                            uploaded_file.getvalue(),
                            "application/json"
                        )
                    }
                )

            # =========================
            # REPO MODE
            # =========================
            elif repo_url:

                response = requests.post(
                    BACKEND_URL + "/analyze-repo",
                    params={
                        "repo_url": repo_url,
                        "branch": branch
                    }
                )

            else:
                st.error("Input non valido")
                st.stop()

            if response.status_code != 200:
                st.error(response.text)
                st.stop()

            result = response.json()

            st.success("Analisi completata")

            # ====================================================
            # UNIFIED DATA MODEL
            # ====================================================

            dependencies = result.get("dependencies", [])
            git_repos = result.get("detected_git_repos", [])

            # ====================================================
            # TABS (SEMPRE UGUALI)
            # ====================================================

            tab1, tab2, tab3 = st.tabs([
                "📦 Componenti" + f" ({len(dependencies)})",
                "🐳 GitHub Repos",
                "📊 SBOM Export"
            ])

            # ====================================================
            # TAB 1 - COMPONENTI
            # ====================================================

            with tab1:

                if dependencies:

                    df = pd.DataFrame(dependencies)

                    cols = [
                        "type",
                        "component_type",
                        "name",
                        "version",
                        "purl",
                        "language",
                        "github_repo"
                    ]

                    df = df[cols]

                    df.columns = [
                        "Tipo Installazione",
                        "Tipo Componente",
                        "Nome / Risorsa",
                        "Versione",
                        "PURL",
                        "Linguaggio",
                        "Repo GitHub"
                    ]

                    st.dataframe(df, use_container_width=True)

                    st.download_button(
                        "⬇️ Scarica JSON componenti",
                        json.dumps(dependencies, indent=2),
                        "components.json",
                        "application/json"
                    )

                else:
                    st.info("Nessun componente trovato")

            # ====================================================
            # TAB 2 - REPOS
            # ====================================================

            with tab2:

                if git_repos:

                    for r in git_repos:
                        st.markdown(f"- 🔗 {r}")

                else:
                    st.info("Nessuna repository GitHub trovata")

            # ====================================================
            # TAB 3 - EXPORT
            # ====================================================

            with tab3:

                st.code(json.dumps(result, indent=2), language="json")

                st.download_button(
                    "⬇️ Scarica SBOM completo",
                    json.dumps(result, indent=2),
                    "sbom.json",
                    "application/json"
                )

        except requests.exceptions.ConnectionError:
            st.error("Backend non raggiungibile")