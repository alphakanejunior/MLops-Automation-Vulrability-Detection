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

# ==========================================================
# CLI ARGUMENTS
# ==========================================================
parser = argparse.ArgumentParser(description="CVE Enrichment Tool")
parser.add_argument("--nvd-db", required=True, help="Chemin du fichier NVD JSON local")
parser.add_argument("--bandit-report", required=False, help="Fichier ou dossier Bandit")
parser.add_argument("--dependency-report", required=False, help="Fichier ou dossier dépendances")
parser.add_argument("--modelscan-report", required=False, help="Fichier ou dossier ModelScan")
parser.add_argument("--container-reports", required=False, help="Pattern pour fichiers conteneur (Trivy)")
parser.add_argument("--output", required=True, help="Chemin de sortie du fichier enrichi")
args = parser.parse_args()

NVD_JSON_PATH = Path(args.nvd_db)
OUTPUT_FILE = Path(args.output)
os.makedirs(OUTPUT_FILE.parent, exist_ok=True)

# ==========================================================
# LOAD JSON
# ==========================================================
def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
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
# LOAD NVD
# ==========================================================
print("🔄 Loading NVD database...")
nvd_raw = load_json(NVD_JSON_PATH)
nvd_data = {}

for item in nvd_raw.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        continue

    descs = cve.get("descriptions", [])
    descr = ""
    for d in descs:
        if d.get("lang") == "en":
            descr = d.get("value")
            break

    metrics = item.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

    nvd_data[cve_id] = {
        "description": descr,
        "cvss_v2": {},
        "cvss_v3": cvss_v3,
        "severity": cvss_v3.get("baseSeverity", ""),
        "exploitability": "",
        "patch": "",
        "source": "NVD"
    }

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
        for file in path_obj.glob("**/*"):
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
    for file in Path().glob(args.container_reports):
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
