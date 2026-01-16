#!/usr/bin/env python3
import os
import glob
import json
from tabulate import tabulate
import argparse

# ==========================
# Arguments
# ==========================
parser = argparse.ArgumentParser(description="Enrich Bandit scan results with NVD CVEs")
parser.add_argument("--nvd-db", required=True, help="Folder containing NVD JSON files")
parser.add_argument("--bandit-report", required=True, help="Folder containing Bandit JSON report")
parser.add_argument("--output", required=True, help="Output JSON file for enriched CVEs")
args = parser.parse_args()

# ==========================
# Charger NVD
# ==========================
print("🔄 Chargement NVD 2.0…")
nvd_db = {}
for nvd_file in glob.glob(os.path.join(args.nvd_db, "*.json")):
    with open(nvd_file) as f:
        data = json.load(f)
        for item in data.get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            # Extraire les CWE pour chaque CVE
            cwes = []
            for pt in item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []):
                for desc in pt.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwes.append(desc["value"].replace("CWE-", ""))
            nvd_db[cve_id] = {
                "item": item,
                "cwes": cwes
            }
print(f"📊 CVE NVD chargées : {len(nvd_db)}")

# ==========================
# Charger Bandit
# ==========================
bandit_json_file = glob.glob(os.path.join(args.bandit_report, "*.json"))[0]
with open(bandit_json_file) as f:
    bandit_data = json.load(f)

bandit_results = bandit_data.get("results", [])
print(f"🔍 Vulnérabilités détectées par Bandit : {len(bandit_results)}")

# ==========================
# Enrichissement
# ==========================
enriched = {}

for v in bandit_results:
    cwe_id = str(v.get("issue_cwe", {}).get("id", "N/A"))

    enriched[cwe_id] = {
        "description": "",
        "cvss_score": "",
        "cvss_vector": "",
        "severity": "",
        "exploitability": "",
        "patch": "",
        "source": "ReportOnly",
        "file": v.get("filename"),
        "line": v.get("line_number"),
        "issue_text": v.get("issue_text"),
        "test_id": v.get("test_id"),
        "test_name": v.get("test_name"),
        "more_info": v.get("more_info")
    }

    # Mapper avec NVD
    for cve_id, nvd_entry in nvd_db.items():
        if cwe_id in nvd_entry["cwes"]:
            item = nvd_entry["item"]
            # Récupérer description
            desc = item.get("cve", {}).get("description", {}).get("description_data", [])
            description = desc[0]["value"] if desc else ""
            # Récupérer CVSSv3
            cvss = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
            severity = cvss.get("baseSeverity", "")
            baseScore = cvss.get("baseScore", "")
            vector = cvss.get("vectorString", "")
            exploitability = item.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore", "")

            enriched[cwe_id].update({
                "description": description,
                "cvss_score": baseScore,
                "cvss_vector": vector,
                "severity": severity,
                "exploitability": exploitability,
                "source": "NVD"
            })
            break  # on prend le premier CVE trouvé

# ==========================
# Affichage console
# ==========================
table = []
for cwe, info in enriched.items():
    table.append([
        cwe,
        info["file"],
        info["line"],
        info["severity"],
        info["cvss_score"],
        info["exploitability"],
        info["issue_text"],
        info["test_id"],
        info["test_name"],
        info["more_info"]
    ])

print("\n🔍 Bandit Scan Enrichi avec NVD :")
print(tabulate(
    table,
    headers=["CWE", "File", "Line", "Severity", "CVSSv3", "Exploitability", "Issue", "Test ID", "Test Name", "More Info"],
    tablefmt="github"
))

# ==========================
# Export JSON final
# ==========================
os.makedirs(os.path.dirname(args.output), exist_ok=True)
with open(args.output, "w") as f:
    json.dump(enriched, f, indent=2)

print(f"\n✅ Rapport enrichi sauvegardé : {args.output}")
