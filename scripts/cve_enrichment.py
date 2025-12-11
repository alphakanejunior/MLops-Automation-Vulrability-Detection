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
# ARGUMENTS CLI
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
# JSON LOADER
# ==========================================================
def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        print(f"⚠️ Impossible de lire {path}")
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
            cwe = item.get("issue_cwe", {}).get("id")
            if cwe:
                cves.append(f"CWE-{cwe}")
    return cves


def extract_dependency_cves(report):
    """
    pip-audit format:
    {
      "dependencies": [
        {
          "name": "package",
          "version": "x.y.z",
          "vulns": [
            {"id": "CVE-XXXX-YYYY", ...}
          ]
        }
      ]
    }
    """
    cves = []
    for pkg in report.get("dependencies", []):
        vulns = pkg.get("vulns", [])

        # si aucune vulnérabilité → on crée un identifiant unique
        if not vulns:
            cves.append(f"{pkg['name']}@{pkg['version']}")
            continue

        for v in vulns:
            cves.append(v.get("id", f"{pkg['name']}@{pkg['version']}"))

    return cves


def extract_modelscan_cves(report):
    """
    ModelScan renvoie parfois :
    {
      "vulnerabilities": [
        {"cve": "CVE-XXXX", "id": "..."}
      ]
    }
    """
    vulns = []
    for v in report.get("vulnerabilities", []):
        if "cve" in v and v["cve"]:
            vulns.append(v["cve"])
        else:
            vulns.append(v.get("id", "ModelScan-UNKNOWN"))
    return vulns


def extract_trivy_cves(report):
    cves = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cves.append(vuln.get("VulnerabilityID", "TRIVY-UNKNOWN"))
        for misconf in result.get("Misconfigurations", []):
            cves.append(misconf.get("AVDID", "TRIVY-MISCONFIG-UNKNOWN"))
    return cves

# ==========================================================
# LOAD NVD DATABASE
# ==========================================================
print("🔄 Loading NVD database...")
nvd_raw = load_json(NVD_JSON_PATH)
nvd_data = {}

for item in nvd_raw.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        continue

    # description EN
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS v3
    cvss_v3 = {}
    metrics = item.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {})

    nvd_data[cve_id] = {
        "description": desc,
        "cvss_v2": {},
        "cvss_v3": cvss_v3,
        "severity": cvss_v3.get("baseSeverity", ""),
        "exploitability": "",
        "patch": "",
        "source": "NVD"
    }

# ==========================================================
# COLLECT VULNERABILITIES
# ==========================================================
print("🔍 Collecting vulnerabilities...")

all_vulns = set()

if args.bandit_report:
    all_vulns.update(extract_bandit_cves(load_json(args.bandit_report)))

if args.dependency_report:
    all_vulns.update(extract_dependency_cves(load_json(args.dependency_report)))

if args.modelscan_report:
    try:
        all_vulns.update(extract_modelscan_cves(load_json(args.modelscan_report)))
    except json.JSONDecodeError:
        print(f"⚠️ Invalid ModelScan JSON: {args.modelscan_report}")

if args.container_reports:
    for file in Path().glob(args.container_reports):
        all_vulns.update(extract_trivy_cves(load_json(file)))

print(f"➡️ {len(all_vulns)} vulnerabilities collected.")

# ==========================================================
# ENRICH WITH NVD
# ==========================================================
print("🔍 Enriching vulnerabilities with NVD...")

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
# SAVE JSON OUTPUT
# ==========================================================
with open(OUTPUT_FILE, "w") as f:
    json.dump(enriched, f, indent=2)

print(f"✅ Enriched report saved to {OUTPUT_FILE}")

# ==========================================================
# HUMAN-READABLE TABLE
# ==========================================================
if enriched:
    print("\nVulnerability Enriched Report:\n")
    table = [
        [
            v,
            info["description"][:80],
            info["cvss_v2"].get("baseScore", ""),
            info["cvss_v3"].get("baseScore", ""),
            info["severity"],
            info["source"]
        ]
        for v, info in enriched.items()
    ]

    print(tabulate(
        table,
        headers=["ID", "Description", "CVSSv2", "CVSSv3", "Severity", "Source"],
        tablefmt="grid"
    ))
else:
    print("⚠️ No vulnerabilities found.")
