#!/usr/bin/env python3
"""
cve_enrichment.py
Enrichit les vulnérabilités détectées dans Bandit, pip-audit, ModelScan et Trivy
avec les données NVD 2.0 et exporte un fichier JSON consolidé.
Même si la vulnérabilité n'a pas de correspondance NVD, elle sera conservée.
"""

import json
import os
import argparse
import re
from pathlib import Path
from tabulate import tabulate
import glob

# ==========================================================
# CLI ARGUMENTS
# ==========================================================
parser = argparse.ArgumentParser(description="CVE Enrichment Tool")
parser.add_argument("--nvd-db", required=True, help="Chemin du dossier contenant tous les fichiers NVD JSON")
parser.add_argument("--bandit-report", required=False, help="Fichier ou dossier Bandit")
parser.add_argument("--dependency-report", required=False, help="Fichier ou dossier dépendances")
parser.add_argument("--modelscan-report", required=False, help="Fichier ou dossier ModelScan")
parser.add_argument("--container-reports", required=False, help="Pattern pour fichiers conteneur (Trivy)")
parser.add_argument("--output", required=True, help="Chemin de sortie du fichier enrichi")
args = parser.parse_args()

OUTPUT_FILE = Path(args.output)
os.makedirs(OUTPUT_FILE.parent, exist_ok=True)

# ==========================================================
# LOAD JSON
# ==========================================================
def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not data:
                raise ValueError("Fichier vide")
            return data
    except Exception as e:
        print(f"⚠️ Impossible de lire {path}: {e}")
        return {}

# ==========================================================
# EXTRACT VULNERABILITIES
# ==========================================================
def extract_bandit_cves(report):
    cves = []
    for item in report.get("results", []):
        found = re.findall(r"CVE-\d{4}-\d{4,7}", item.get("issue_text", ""))
        if found:
            cves.extend(found)
        else:
            cwe_id = item.get("issue_cwe", {}).get("id")
            if cwe_id:
                cves.append(f"CWE-{cwe_id}")
    return cves

def extract_dependency_cves(report):
    cves = []
    for pkg in report.get("dependencies", []):
        for v in pkg.get("vulns", []):
            cves.append(v.get("id", f"{pkg['name']}@{pkg['version']}"))
    return cves

def extract_modelscan_cves(report):
    return [item.get("cve", f"{item.get('id', 'modelscan-unknown')}") for item in report.get("vulnerabilities", [])]

def extract_trivy_cves(report):
    cves = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cves.append(vuln.get("VulnerabilityID", "TRIVY-UNKNOWN"))
        for misconf in result.get("Misconfigurations", []):
            cves.append(misconf.get("AVDID", "TRIVY-MISCONFIG-UNKNOWN"))
    return cves

# ==========================================================
# LOAD ALL NVD FILES (NVD 2.0)
# ==========================================================
print("🔄 Loading NVD database from folder:", args.nvd_db)
nvd_data = {}

nvd_path = Path(args.nvd_db)

if not nvd_path.exists():
    print("❌ NVD path not found")
    exit(1)

nvd_files = list(nvd_path.glob("*.json"))
if not nvd_files:
    print("❌ No NVD JSON files found")
    exit(1)

for nvd_file in nvd_files:
    print(f"🔄 Loading {nvd_file}")
    nvd_raw = load_json(nvd_file)

    for item in nvd_raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # Description
        descr = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                descr = d.get("value")
                break

        # CVSS v3.1
        metrics = item.get("metrics", {})
        cvss_v3 = {}
        severity = ""

        if "cvssMetricV31" in metrics:
            cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {})
            severity = cvss_v3.get("baseSeverity", "")
        elif "cvssMetricV30" in metrics:
            cvss_v3 = metrics["cvssMetricV30"][0].get("cvssData", {})
            severity = cvss_v3.get("baseSeverity", "")

        nvd_data[cve_id] = {
            "description": descr,
            "cvss_v2": {},
            "cvss_v3": cvss_v3,
            "severity": severity,
            "exploitability": "",
            "patch": "",
            "source": "NVD"
        }

print(f"📊 CVE chargées depuis la NVD : {len(nvd_data)}")

# ==========================================================
# COLLECT ALL VULNERABILITIES
# ==========================================================
print("🔍 Collecting vulnerabilities...")
all_vulns = set()

def add_report(path, extractor):
    path_obj = Path(path)
    if not path_obj.exists():
        print(f"⚠️ Report {path} not found")
        return
    if path_obj.is_file():
        report = load_json(path_obj)
        all_vulns.update(extractor(report))
    elif path_obj.is_dir():
        for file in path_obj.glob("**/*.json"):
            if file.is_file():
                report = load_json(file)
                all_vulns.update(extractor(report))

if args.bandit_report:
    add_report(args.bandit_report, extract_bandit_cves)

if args.dependency_report:
    add_report(args.dependency_report, extract_dependency_cves)

if args.modelscan_report:
    add_report(args.modelscan_report, extract_modelscan_cves)

if args.container_reports:
    # Récupération récursive des fichiers container
    for file in Path().rglob(args.container_reports):
        if file.is_file():
            report = load_json(file)
            all_vulns.update(extract_trivy_cves(report))

# ==========================================================
# ENRICH
# ==========================================================
print(f"🔍 Enriching {len(all_vulns)} vulnerabilities with NVD data...")

enriched = {}
for vuln in all_vulns:
    if vuln in nvd_data:
        enriched[vuln] = nvd_data[vuln]
    else:
        enriched[vuln] = {
            "description": "",
            "cvss_v2": {},
            "cvss_v3": {},
            "severity": "",
            "exploitability": "",
            "patch": "",
            "source": "ReportOnly"
        }

# ==========================================================
# SAVE JSON
# ==========================================================
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(enriched, f, indent=2)

print(f"✅ Enriched report saved to {OUTPUT_FILE}")

# ==========================================================
# HUMAN TABLE OUTPUT
# ==========================================================
table = [
    [
        v,
        info["description"][:80],
        info["cvss_v2"].get("baseScore", ""),
        info["cvss_v3"].get("baseScore", ""),
        info["severity"],
        info["exploitability"],
        info["patch"],
        info.get("source", "")
    ]
    for v, info in enriched.items()
]

if table:
    print("\nVulnerability Enriched Report:\n")
    print(tabulate(
        table,
        headers=["ID", "Description", "CVSSv2", "CVSSv3", "Severity", "Exploitability", "Patch", "Source"],
        tablefmt="grid"
    ))
else:
    print("⚠️ No vulnerabilities found to enrich.")
