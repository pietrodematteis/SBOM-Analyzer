from fastapi import FastAPI, UploadFile, File, HTTPException, Query
import json
import subprocess
from dotenv import load_dotenv
import os
import re
import requests
from functools import lru_cache
import tempfile
import shutil

load_dotenv()

app = FastAPI(title="TLSAssistant Dependency Analyzer Backend")

GITHUB_API = "https://api.github.com/repos"


# ============================================================
# AUTH GITHUB
# ============================================================

def github_headers():
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}
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
# GITHUB METADATA
# ============================================================

@lru_cache(maxsize=128)
def fetch_github_metadata(repo_url: str) -> dict:

    if repo_url == "N/A":
        return {}

    try:
        parts = repo_url.rstrip("/").split("/")
        owner = parts[-2]
        repo = parts[-1]

        r = requests.get(
            f"{GITHUB_API}/{owner}/{repo}",
            headers=github_headers(),
            timeout=5
        )

        if r.status_code != 200:
            return {}

        data = r.json()

        return {
            "language": data.get("language"),
            "stars": data.get("stargazers_count"),
            "default_branch": data.get("default_branch"),
            "description": data.get("description")
        }

    except Exception:
        return {}


# ============================================================
# PYPI METADATA
# ============================================================

@lru_cache(maxsize=128)
def fetch_pypi_metadata(package_name: str) -> dict:

    try:
        r = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=5
        )

        if r.status_code != 200:
            return {}

        info = r.json().get("info", {})

        github_repo = "N/A"

        for v in info.get("project_urls", {}).values():
            if v and "github.com" in v.lower():
                github_repo = parse_github_url(v)
                break

        if github_repo == "N/A":
            home = info.get("home_page", "")
            if "github.com" in home.lower():
                github_repo = parse_github_url(home)

        return {
            "github_repo": github_repo,
            "license": info.get("license")
        }

    except Exception:
        return {}


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

    if version:
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
# MAIN ANALYZE (FILE)
# ============================================================

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    try:

        data = json.loads(await file.read())

        results = []
        repos = []

        for item in data:

            t = item.get("type")

            name, version, purl = extract(item)

            repo = parse_github_url(item.get("url", ""))

            if repo != "N/A":
                repos.append(repo)

            results.append({
                "type": t,
                "name": name,
                "version": version,
                "purl": purl,
                "github_repo": repo
            })

        return {
            "status": "ok",
            "count": len(results),
            "dependencies": results,
            "detected_git_repos": list(set(repos))
        }

    except Exception as e:
        raise HTTPException(400, str(e))

# ====================================================
# Analyze Repository (URL)
# ====================================================

@app.post("/analyze-repo")
def analyze_repo(repo_url: str, branch: str = "main"):

    tmp = tempfile.mkdtemp()

    try:
        # ====================================================
        # CLONE REPO
        # ====================================================
        subprocess.run([
            "git", "clone",
            "--depth", "1",
            "--branch", branch,
            repo_url,
            tmp
        ], check=True)

        # ====================================================
        # SEARCH dependencies.json
        # ====================================================
        target_file = None

        for root, _, files in os.walk(tmp):
            if "dependencies.json" in files:
                target_file = os.path.join(root, "dependencies.json")
                break

        if not target_file:
            return {
                "status": "error",
                "message": "dependencies.json non trovato nella repository"
            }

        # ====================================================
        # LOAD FILE
        # ====================================================
        with open(target_file, "r", encoding="utf-8") as f:
            dependencies = json.load(f)

        if not isinstance(dependencies, list):
            return {
                "status": "error",
                "message": "dependencies.json non valido (deve essere una lista)"
            }

        # ====================================================
        # REUSE YOUR EXISTING LOGIC (inline analysis)
        # ====================================================
        extracted_data = []
        repos = []

        for item in dependencies:

            dep_type = item.get("type", "N/A")
            url_val = item.get("url") or item.get("path") or ""

            name, version, purl = extract(item)
            language = None
            component_type = classify(dep_type)

            github_repo = parse_github_url(item.get("url", ""))

            if github_repo != "N/A":
                repos.append(github_repo)

            extracted_data.append({
                "type": dep_type,
                "component_type": component_type,
                "name": name,
                "version": version,
                "purl": purl,
                "language": language,
                "github_repo": github_repo
            })

        # ====================================================
        # RETURN SAME FORMAT AS /analyze
        # ====================================================
        return {
            "status": "success",
            "repo": repo_url,
            "branch": branch,
            "count": len(extracted_data),
            "dependencies": extracted_data,
            "detected_git_repos": list(set(repos))
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================
# DOCKER SBOM
# ============================================================

@app.post("/analyze-docker")
def analyze_docker(image: str):

    r = subprocess.run([
        "trivy", "image",
        "--format", "json",
        image
    ], capture_output=True, text=True)

    return {
        "image": image,
        "sbom": json.loads(r.stdout) if r.stdout else {}
    }


# ============================================================
# SBOM COMPARE
# ============================================================

def extract_purls(sbom):

    purls = set()

    for r in sbom.get("Results", []):
        for p in r.get("Packages", []):
            name = p.get("Name")
            ver = p.get("Version")

            if name:
                purls.add(f"{name}@{ver}" if ver else name)

    return purls


@app.post("/sbom/compare")
def compare(repo_sbom: dict, docker_sbom: dict):

    repo = extract_purls(repo_sbom)
    docker = extract_purls(docker_sbom)

    return {
        "only_in_repo": list(repo - docker),
        "only_in_docker": list(docker - repo),
        "common": list(repo & docker)
    }


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)