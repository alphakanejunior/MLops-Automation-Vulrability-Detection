#!/usr/bin/env python3
"""
cve_enrichment.py
Enrichit les vulnérabilités détectées dans Bandit, pip-audit, ModelScan et Trivy
avec les données NVD 2.0 et exporte un fichier JSON consolidé.
Même si la vulnérabilité n'a pas de correspondance NVD, elle sera conservée.
Affiche deux tableaux séparés : NVD et autres.
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
parser.add_argument("--nvd-db", required=True, help="Chemin du dossier/fichier NVD JSON")
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
# LOAD NVD
# ==========================================================
print("🔄 Chargement NVD 2.0…")
nvd_data = {}

nvd_files = []
if os.path.isfile(args.nvd_db):
    nvd_files = [args.nvd_db]
else:
    nvd_files = glob.glob(f"{args.nvd_db}/*.json")

total_cve = 0
for nvd_file in nvd_files:
    nvd_raw = load_json(nvd_file)
    for item in nvd_raw.get("CVE_Items", []):
        cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
        cve_id = cve_meta.get("ID")
        if not cve_id:
            continue

        # Description
        descs = item.get("cve", {}).get("description", {}).get("description_data", [])
        descr = ""
        for d in descs:
            if d.get("lang") == "en":
                descr = d.get("value")
                break

        # CVSS
        impact = item.get("impact", {})
        cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
        cvss_v2 = impact.get("baseMetricV2", {})

        nvd_data[cve_id] = {
            "description": descr,
            "cvss_v2": cvss_v2,
            "cvss_v3": cvss_v3,
            "severity": cvss_v3.get("baseSeverity", ""),
            "exploitability": cvss_v3.get("attackVector","") if cvss_v3 else "",
            "patch": "",
            "source": "NVD"
        }
        total_cve += 1

print(f"📊 CVE chargées : {total_cve}")

# ==========================================================
# COLLECT VULNERABILITIES
# ==========================================================
print("🔍 Collecte des vulnérabilités…")
all_vulns = set()

def add_report(path, extractor):
    path_obj = Path(path)
    if not path_obj.exists():
        print(f"⚠️ Report {path} non trouvé")
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
    for file in Path().rglob(args.container_reports):
        if file.is_file():
            report = load_json(file)
            all_vulns.update(extract_trivy_cves(report))

print(f"🔍 Total vulnérabilités détectées : {len(all_vulns)}")

# ==========================================================
# ENRICH
# ==========================================================
enriched = {}
for vuln in all_vulns:
    if vuln in nvd_data:
        enriched[vuln] = nvd_data[vuln]
    else:
        # Assign CWE severity example
        severity = ""
        if vuln.startswith("CWE-"):
            # Exemple mapping simple
            cwe_severity = {"CWE-259": "HIGH", "CWE-605":"MEDIUM", "CWE-78":"MEDIUM"}
            severity = cwe_severity.get(vuln, "")
        enriched[vuln] = {
            "description": "Faiblesse de sécurité (CWE)" if vuln.startswith("CWE-") else "",
            "cvss_v2": {},
            "cvss_v3": {"baseScore": ""} ,
            "severity": severity,
            "exploitability": "",
            "patch": "",
            "source": "ReportOnly" if not vuln.startswith("CWE-") else "CWE"
        }

# ==========================================================
# SAVE JSON
# ==========================================================
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(enriched, f, indent=2)

print(f"✅ Rapport enrichi sauvegardé : {OUTPUT_FILE}")

# ==========================================================
# DISPLAY TABLES
# ==========================================================
# Séparer NVD et autres
nvd_vulns = {v: info for v, info in enriched.items() if info.get("source") == "NVD"}
other_vulns = {v: info for v, info in enriched.items() if info.get("source") != "NVD"}

# Tableau NVD
if nvd_vulns:
    table_nvd = [
        [
            v,
            info["severity"],
            info["cvss_v3"].get("baseScore", ""),
            info["exploitability"],
            info.get("source", ""),
            info["description"][:80]
        ]
        for v, info in nvd_vulns.items()
    ]
    print("\nVulnerabilités NVD :\n")
    print(tabulate(
        table_nvd,
        headers=["ID", "Severity", "CVSSv3", "Exploitability", "Source", "Description"],
        tablefmt="grid"
    ))

# Tableau autres vulnérabilités
if other_vulns:
    table_other = [
        [
            v,
            info.get("severity",""),
            info.get("cvss_v3", {}).get("baseScore",""),
            info.get("exploitability",""),
            info.get("source",""),
            info.get("description","")[:80]
        ]
        for v, info in other_vulns.items()
    ]
    print("\nAutres vulnérabilités (CWE / PYSEC / AVD / ReportOnly) :\n")
    print(tabulate(
        table_other,
        headers=["ID", "Severity", "CVSSv3", "Exploitability", "Source", "Description"],
        tablefmt="grid"
    ))
