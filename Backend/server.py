from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
import json
import subprocess
from dotenv import load_dotenv
import os
import re
import requests
import tempfile
import shutil
import time
import zipfile  # <- REINSERITO IMPORT MANCANTE
from typing import Optional

load_dotenv()

app = FastAPI(title="TLSAssistant Dependency Analyzer Backend")

STORAGE_DIR = os.path.join(tempfile.gettempdir(), "tlsassistant_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

GITHUB_API = "https://api.github.com/repos"
MY_GITHUB_OWNER = os.getenv("MY_GITHUB_OWNER", "IlTuoNomeUtenteGitHub")
MY_GITHUB_REPO = os.getenv("MY_GITHUB_REPO", "IlNomeDellaTuaRepoDelTool")


# ============================================================
# AUTH GITHUB
# ============================================================

def github_headers():
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }
    return {}


# ============================================================
# GITHUB PARSER
# ============================================================

def parse_github_url(url: str) -> str:
    if not url or not isinstance(url, str):
        return "N/A"

    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", url)

    if not match:
        return "N/A"

    owner = match.group(1)
    repo = match.group(2).replace(".git", "")

    return f"https://github.com/{owner}/{repo}"


# ============================================================
# PURL
# ============================================================

def build_purl(dep_type: str, name: str, version: str | None = None):
    if dep_type == "pip":
        return f"pkg:pypi/{name}" + (f"@{version}" if version else "")
    if dep_type == "apt":
        return f"pkg:deb/debian/{name}"
    if dep_type in ["git", "git-submodule"]:
        return f"pkg:github/{name}"
    if version and version != "unknown":
        return f"pkg:generic/{name}@{version}"
    return f"pkg:generic/{name}"


# ============================================================
# CLASSIFIER
# ============================================================

def classify(dep_type: str):
    return {
        "pip": "library",
        "apt": "system",
        "git": "app",
        "git-submodule": "app",
        "zip": "binary",
        "file": "data",
        "cfg": "config",
        "compile_maven": "build"
    }.get(dep_type, "unknown")


# ============================================================
# EXTRACT
# ============================================================

def extract(item):
    t = item.get("type")
    val = item.get("url") or item.get("path") or ""

    name = val
    version = "unknown"

    if t == "pip":
        if "==" in val:
            name, version = val.split("==")
    elif t in ["git", "git-submodule"]:
        repo = parse_github_url(val)
        if repo != "N/A":
            name = repo.split("/")[-1]
    elif t in ["zip", "file"]:
        name = val.split("/")[-1]

    purl = build_purl(t, name, None if version == "unknown" else version)
    return name, version, purl


# ============================================================
# LOGICA DI POLLING E SCARICAMENTO ARTIFACT
# ============================================================

def wait_and_download_artifacts(run_id: int, dest_dir: str):
    """Attende il completamento della Run e scarica l'artifact risultante."""
    headers = github_headers()
    url_run = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs/{run_id}"
    
    # 1. Polling sullo stato della run (Timeout massimo 10 minuti)
    for _ in range(120):  
        print(f"Controllo stato run ID {run_id}...")
        res = requests.get(url_run, headers=headers)
        if res.status_code == 200:
            status = res.json().get("status")
            conclusion = res.json().get("conclusion")
            if status == "completed":
                if conclusion != "success":
                    raise Exception(f"La GitHub Action è terminata con stato: {conclusion}")
                break
        time.sleep(5)
    else:
        raise Exception("Timeout: La GitHub Action ha impiegato troppo tempo.")

    # Recupero dell'ID dell'Artifact
    url_artifacts = f"{url_run}/artifacts"
    res_art = requests.get(url_artifacts, headers=headers)
    if res_art.status_code != 200:
        return

    artifacts = res_art.json().get("artifacts", [])
    target_artifact = next((a for a in artifacts if a["name"] == "sbom-static-results"), None)
    
    if not target_artifact:
        return

    # 3. Download del pacchetto ZIP dell'artifact
    download_url = target_artifact["archive_download_url"]
    res_dl = requests.get(download_url, headers=headers, stream=True)
    if res_dl.status_code == 200:
        zip_path = os.path.join(dest_dir, "artifacts.zip")
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(res_dl.raw, f)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)


def trigger_github_action(repo_url: str, branch: str, format_type: str) -> Optional[dict]:
    """Innesca la pipeline remota e restituisce dizionario con URL e Run ID."""
    headers = github_headers()
    if not headers:
        return None

    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url)
    owner_repo = f"{match.group(1)}/{match.group(2).replace('.git', '')}" if match else repo_url

    url_dispatch = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/workflows/main.yml/dispatches"
    payload = {
        "ref": "main",
        "inputs": {
            "src_repository": owner_repo,
            "src_branch": branch,
            "format": format_type
        }
    }

    res = requests.post(url_dispatch, headers=headers, json=payload)
    if res.status_code != 204:
        return None

    time.sleep(6)
    
    url_runs = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs?per_page=1"
    res_runs = requests.get(url_runs, headers=headers)
    if res_runs.status_code == 200:
        runs = res_runs.json().get("workflow_runs", [])
        if runs:
            return {
                "html_url": runs[0].get("html_url"),
                "id": runs[0].get("id")
            }
            
    return None


# ============================================================
# ACQUISIZIONE E SALVATAGGIO IN MEMORIA SERVER
# ============================================================

@app.post("/upload-sbom")
async def upload_sbom(
    action: str = Form(...),
    requirements_file: Optional[UploadFile] = File(None),
    poetry_file: Optional[UploadFile] = File(None),
):
    if os.path.exists(STORAGE_DIR):
        shutil.rmtree(STORAGE_DIR)
    os.makedirs(STORAGE_DIR, exist_ok=True)

    if action == "upload":
        if not requirements_file and not poetry_file:
            raise HTTPException(400, "Carica almeno uno dei due file.")

        if requirements_file:
            with open(os.path.join(STORAGE_DIR, "trivy_requirements.json"), "wb") as f:
                f.write(await requirements_file.read())

        if poetry_file:
            with open(os.path.join(STORAGE_DIR, "trivy_poetry.json"), "wb") as f:
                f.write(await poetry_file.read())

        return {"status": "success", "message": "File manuali salvati sul server."}

    elif action == "generate":
        return {"status": "success", "message": "Pronto per l'attivazione della pipeline di generazione remota."}


# ============================================================
# ANALISI COMPARATIVA INTEGRATA (Corretta 🛠️)
# ============================================================

@app.post("/compare-dependencies")
def compare_dependencies(repo_url: str, branch: str, path_dipendenze: str, format: str = "entrambi"):
    tmp_clone = tempfile.mkdtemp()
    try:
        github_run_url = None
        
        # 1. Attivazione ed esecuzione del Polling se configurato per generare
        action_info = trigger_github_action(repo_url, branch, format)
        if action_info:
            github_run_url = action_info["html_url"]
            # Questo blocco avvia il ciclo for che vedi sopra con i tuoi "print"
            wait_and_download_artifacts(action_info["id"], STORAGE_DIR)

        # 2. Clonazione locale per estrarre il file di controllo dinamico
        subprocess.run([
            "git", "clone", "--depth", "1", "--branch", branch, repo_url, tmp_clone
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        target_file = None
        for root, _, files in os.walk(tmp_clone):
            if path_dipendenze in files:
                target_file = os.path.join(root, path_dipendenze)
                break

        if not target_file:
            raise HTTPException(404, f"File '{path_dipendenze}' non trovato nella repository.")

        with open(target_file, "r", encoding="utf-8") as f:
            dependencies = json.load(f)

        if not isinstance(dependencies, list):
            raise HTTPException(400, "Il file delle dipendenze deve essere una lista JSON.")

        def extract_identifiers(file_name):
            file_path = os.path.join(STORAGE_DIR, file_name)
            if not os.path.exists(file_path):
                return set()
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                identifiers = set()
                components_list = []

                if isinstance(data, dict) and "components" in data:
                    components_list = data["components"]
                elif isinstance(data, dict) and "artifacts" in data:
                    components_list = data["artifacts"]
                elif isinstance(data, list):
                    components_list = data

                for item in components_list:
                    if isinstance(item, dict):
                        name = item.get("name")
                        if name: identifiers.add(str(name).lower().strip())
                    elif isinstance(item, str):
                        identifiers.add(item.lower().strip())
                return identifiers
            except Exception:
                return set()

        # Leggiamo i file REALI mappati corretti (estratti dall'artifact o caricati)
        req_identifiers = extract_identifiers("trivy_requirements.json")
        poetry_identifiers = extract_identifiers("trivy_poetry.json")

        extracted_data = []
        repos = []
        for item in dependencies:
            dep_type = item.get("type", "N/A")
            name, version, purl = extract(item)
            component_type = classify(dep_type)
            github_repo = parse_github_url(item.get("url", ""))

            if github_repo != "N/A":
                repos.append(github_repo)

            name_clean = str(name).lower().strip()

            is_in_req = "✅" if name_clean in req_identifiers else "❌"
            is_in_poetry = "✅" if name_clean in poetry_identifiers else "❌"

            extracted_data.append({
                "type": dep_type,
                "component_type": component_type,
                "name": name,
                "version": version,
                "purl": purl,
                "url": item.get("url") or item.get("path") or "",
                "github_repo": github_repo,
                "present_in_requirements": is_in_req,
                "present_in_poetry": is_in_poetry
            })

        simulated_matrix = (
            f"=== REPORT REALE PIPELINE ACTIONS ===\n"
            f"Componenti estratti dal file dinamico: {len(extracted_data)}\n"
            f"Trovati in Trivy (Requirements): {len([e for e in extracted_data if e['present_in_requirements'] == '✅'])}\n"
            f"Trovati in Trivy (Poetry): {len([e for e in extracted_data if e['present_in_poetry'] == '✅'])}\n"
        )

        return {
            "status": "success",
            "repo": repo_url,
            "branch": branch,
            "count": len(extracted_data),
            "result": extracted_data,
            "detected_git_repos": list(set(repos)),
            "github_run_url": github_run_url,
            "comparison_matrix": simulated_matrix
        }

    except Exception as e:
        raise HTTPException(500, f"Errore interno del server: {str(e)}")
    finally:
        shutil.rmtree(tmp_clone, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)