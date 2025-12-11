#!/usr/bin/env python3
"""
cve_enrichment.py
Enrichit les CVEs détectées dans Bandit, pip-audit, ModelScan et Trivy
avec les données NVD 2.0 et exporte un fichier JSON consolidé.
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
parser.add_argument("--bandit-report", required=False)
parser.add_argument("--dependency-report", required=False)
parser.add_argument("--modelscan-report", required=False)
parser.add_argument("--container-reports", required=False)
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
        with open(path, "r") as f:
            return json.load(f)
    except:
        return {}


# ==========================================================
# EXTRACT CVEs
# ==========================================================
def extract_cves_from_bandit(report):
    cves = []
    for item in report.get("results", []):
        text = item.get("issue_text", "")
        cves += re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return cves


def extract_cves_from_dependency(report):
    cves = []
    for pkg in report.get("dependencies", []):
        for v in pkg.get("vulns", []):
            if "id" in v:
                cves.append(v["id"])
    return cves


def extract_cves_from_modelscan(report):
    return [item.get("cve") for item in report.get("vulnerabilities", []) if "cve" in item]


def extract_cves_from_trivy(report):
    cves = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if "VulnerabilityID" in vuln:
                cves.append(vuln["VulnerabilityID"])
    return cves


# ==========================================================
# LOAD NVD 2.0 FORMAT
# ==========================================================
print("🔄 Loading NVD database...")

nvd_raw = load_json(NVD_JSON_PATH)

nvd_data = {}

for item in nvd_raw.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cve_id = cve.get("id")

    if not cve_id:
        continue

    # description
    descs = cve.get("descriptions", [])
    descr = ""
    for d in descs:
        if d.get("lang") == "en":
            descr = d.get("value")
            break

    # CVSS v3
    metrics = item.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

    nvd_data[cve_id] = {
        "description": descr,
        "cvss_v2": {},
        "cvss_v3": cvss_v3,
        "severity": cvss_v3.get("baseSeverity", ""),
        "exploitability": "",
        "patch": ""
    }


# ==========================================================
# LOAD ALL REPORTS
# ==========================================================
print("🔍 Collecting CVEs...")

all_cves = set()

if args.bandit_report:
    all_cves.update(extract_cves_from_bandit(load_json(args.bandit_report)))

if args.dependency_report:
    all_cves.update(extract_cves_from_dependency(load_json(args.dependency_report)))

if args.modelscan_report:
    all_cves.update(extract_cves_from_modelscan(load_json(args.modelscan_report)))

# container reports (glob)
if args.container_reports:
    for file in Path().glob(args.container_reports):
        all_cves.update(extract_cves_from_trivy(load_json(file)))


# ==========================================================
# ENRICH
# ==========================================================
print(f"🔍 Enriching {len(all_cves)} CVEs with NVD data...")

enriched = {}

for cve in all_cves:
    enriched[cve] = nvd_data.get(cve, {
        "description": "",
        "cvss_v2": {},
        "cvss_v3": {},
        "severity": "",
        "exploitability": "",
        "patch": ""
    })


# ==========================================================
# SAVE JSON
# ==========================================================
with open(OUTPUT_FILE, "w") as f:
    json.dump(enriched, f, indent=2)

print(f"✅ Enriched report saved to {OUTPUT_FILE}")


# ==========================================================
# HUMAN TABLE OUTPUT
# ==========================================================
table = [
    [
        cve,
        info["description"][:80],
        info["cvss_v2"].get("baseScore", ""),
        info["cvss_v3"].get("baseScore", ""),
        info["severity"],
        info["exploitability"],
        info["patch"]
    ]
    for cve, info in enriched.items()
]

print("\nCVE Enriched Report:\n")
print(tabulate(
    table,
    headers=["CVE", "Description", "CVSSv2", "CVSSv3", "Severity", "Exploitability", "Patch"],
    tablefmt="grid"
))
