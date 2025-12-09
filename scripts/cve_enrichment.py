#!/usr/bin/env python3
"""
cve_enrichment.py
=================
Lit tous les rapports JSON générés par Bandit, pip-audit, ModelScan et Trivy,
extrait toutes les CVEs, enrichit chaque CVE avec les informations de la base NVD locale
et génère un rapport consolidé JSON et tableau lisible.

Structure du dépôt attendue :
- reports/bandit/
- reports/dependency/
- reports/models/
- reports/container/
- nvd_db/nvdcve-1.1-YYYY.json
"""

import json
import os
import re
from pathlib import Path
from tabulate import tabulate

# ----------------------------
# Configuration
# ----------------------------
REPORTS_DIR = Path("reports")
NVD_JSON_PATH = Path("nvd_db/nvdcve-2.0-modified.json")
OUTPUT_DIR = REPORTS_DIR / "cve_enriched"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = OUTPUT_DIR / "cve-report.json"

# ----------------------------
# Fonctions utilitaires
# ----------------------------
def load_json(file_path):
    if not file_path.exists():
        return {}
    with open(file_path, "r") as f:
        return json.load(f)

def extract_cves_from_bandit(report):
    cves = []
    for item in report.get("results", []):
        text = item.get("issue_text", "")
        found = re.findall(r"CVE-\d{4}-\d{4,7}", text)
        for cve in found:
            cves.append(cve)
    return cves

def extract_cves_from_dependency(report):
    cves = []
    for pkg in report.get("dependencies", []):
        for v in pkg.get("vulns", []):
            if "id" in v:
                cves.append(v["id"])
    return cves

def extract_cves_from_modelscan(report):
    cves = []
    for item in report.get("vulnerabilities", []):
        if "cve" in item:
            cves.append(item["cve"])
    return cves

def extract_cves_from_trivy(report):
    cves = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if "VulnerabilityID" in vuln:
                cves.append(vuln["VulnerabilityID"])
    return cves

def enrich_with_nvd(cve_list, nvd_data):
    enriched = {}
    for cve in cve_list:
        entry = nvd_data.get(cve, {})
        enriched[cve] = {
            "description": entry.get("description", ""),
            "cvss_v2": entry.get("cvss_v2", {}),
            "cvss_v3": entry.get("cvss_v3", {}),
            "severity": entry.get("severity", ""),
            "exploitability": entry.get("exploitability", ""),
            "patch": entry.get("patch", "")
        }
    return enriched

# ----------------------------
# Charger la base NVD locale
# ----------------------------
print("🔄 Loading NVD database...")
nvd_raw = load_json(NVD_JSON_PATH)

# Convertir en dict {CVE_ID: data}
nvd_data = {}
for item in nvd_raw.get("CVE_Items", []):
    cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
    if cve_id:
        nvd_data[cve_id] = {
            "description": item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", ""),
            "cvss_v2": item.get("impact", {}).get("baseMetricV2", {}),
            "cvss_v3": item.get("impact", {}).get("baseMetricV3", {}),
            "severity": item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", ""),
            "exploitability": item.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore", ""),
            "patch": ""  # Optionnel: à remplir si info disponible
        }

# ----------------------------
# Lire tous les rapports
# ----------------------------
all_cves = set()

# Bandit
bandit_reports = sorted(Path(REPORTS_DIR / "bandit").glob("**/*.json"))
for report_file in bandit_reports:
    report = load_json(report_file)
    all_cves.update(extract_cves_from_bandit(report))

# Dependency
dependency_reports = sorted(Path(REPORTS_DIR / "dependency").glob("**/*.json"))
for report_file in dependency_reports:
    report = load_json(report_file)
    all_cves.update(extract_cves_from_dependency(report))

# ModelScan
model_reports = sorted(Path(REPORTS_DIR / "models").glob("**/*.json"))
for report_file in model_reports:
    report = load_json(report_file)
    all_cves.update(extract_cves_from_modelscan(report))

# Trivy
container_reports = sorted(Path(REPORTS_DIR / "container").glob("**/*.json"))
for report_file in container_reports:
    report = load_json(report_file)
    all_cves.update(extract_cves_from_trivy(report))

# ----------------------------
# Enrichissement CVE avec NVD
# ----------------------------
print(f"🔍 Enriching {len(all_cves)} CVEs with NVD data...")
enriched_cves = enrich_with_nvd(all_cves, nvd_data)

# ----------------------------
# Export JSON
# ----------------------------
with open(OUTPUT_FILE, "w") as f:
    json.dump(enriched_cves, f, indent=2)

# ----------------------------
# Affichage tableau lisible
# ----------------------------
table = []
for cve, info in enriched_cves.items():
    table.append([
        cve,
        info.get("description", "")[:80],  # tronqué pour lisibilité
        info.get("cvss_v2", {}).get("baseScore", ""),
        info.get("cvss_v3", {}).get("baseScore", ""),
        info.get("severity", ""),
        info.get("exploitability", ""),
        info.get("patch", "")
    ])

print("\nCVE Enriched Report:\n")
print(tabulate(table, headers=["CVE","Description","CVSSv2","CVSSv3","Severity","Exploitability","Patch"], tablefmt="grid"))
print(f"\n✅ Enriched report saved to {OUTPUT_FILE}")
