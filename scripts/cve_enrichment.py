#!/usr/bin/env python3
import os
import glob
import json
import argparse
from tabulate import tabulate

# ==========================================================
# Arguments
# ==========================================================
parser = argparse.ArgumentParser(
    description="Security Enrichment: Code (Bandit) + Dependencies (Trivy) with NVD"
)
parser.add_argument("--nvd-db", required=True, help="Folder containing NVD JSON files")
parser.add_argument("--bandit-report", required=True, help="Folder containing Bandit JSON report")
parser.add_argument("--trivy-report", required=True, help="Trivy dependency JSON report")
parser.add_argument("--output", required=True, help="Final enriched JSON report")
args = parser.parse_args()

# ==========================================================
# Load NVD (for CODE CWE → CVE mapping)
# ==========================================================
print("🔄 Chargement NVD 2.0 (CWE mapping)…")
nvd_cwe_index = []

for nvd_file in glob.glob(os.path.join(args.nvd_db, "*.json")):
    with open(nvd_file, "r") as f:
        data = json.load(f)
        for item in data.get("CVE_Items", []):
            cwes = []
            for pt in item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []):
                for desc in pt.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwes.append(desc["value"].replace("CWE-", ""))

            if cwes:
                nvd_cwe_index.append({
                    "cwes": cwes,
                    "item": item
                })

print(f"📊 CVE NVD indexées (avec CWE) : {len(nvd_cwe_index)}")

# ==========================================================
# Load Bandit report (CODE)
# ==========================================================
bandit_file = glob.glob(os.path.join(args.bandit_report, "*.json"))[0]
with open(bandit_file, "r") as f:
    bandit_data = json.load(f)

bandit_results = bandit_data.get("results", [])
print(f"🔍 Vulnérabilités CODE détectées : {len(bandit_results)}")

# ==========================================================
# Enrich CODE vulnerabilities
# ==========================================================
code_vulns = []

for v in bandit_results:
    cwe_id = str(v.get("issue_cwe", {}).get("id", "N/A"))
    enriched = {
        "type": "code",
        "cwe": f"CWE-{cwe_id}",
        "file": v.get("filename"),
        "line": v.get("line_number"),
        "issue": v.get("issue_text"),
        "severity": "",
        "cvss_score": "",
        "cvss_vector": "",
        "exploitability": "",
        "source": "Bandit"
    }

    # CWE → CVE → NVD
    for entry in nvd_cwe_index:
        if cwe_id in entry["cwes"]:
            item = entry["item"]
            cvss = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
            enriched.update({
                "severity": cvss.get("baseSeverity", ""),
                "cvss_score": cvss.get("baseScore", ""),
                "cvss_vector": cvss.get("vectorString", ""),
                "exploitability": item.get("impact", {})
                                   .get("baseMetricV3", {})
                                   .get("exploitabilityScore", ""),
                "source": "NVD"
            })
            break

    code_vulns.append(enriched)

# ==========================================================
# Load Trivy report (DEPENDENCIES)
# ==========================================================
with open(args.trivy_report, "r") as f:
    trivy_data = json.load(f)

dependency_vulns = []

for result in trivy_data.get("Results", []):
    target = result.get("Target", "")
    for vuln in result.get("Vulnerabilities", []) or []:
        cvss = vuln.get("CVSS", {}).get("nvd", {})
        dependency_vulns.append({
            "type": "dependency",
            "target": target,
            "package": vuln.get("PkgName"),
            "installed_version": vuln.get("InstalledVersion"),
            "fixed_version": vuln.get("FixedVersion"),
            "cve": vuln.get("VulnerabilityID"),
            "severity": vuln.get("Severity"),
            "cvss_score": cvss.get("V3Score") or cvss.get("V2Score"),
            "description": vuln.get("Title"),
            "reference": vuln.get("PrimaryURL"),
            "source": "NVD"
        })

print(f"📦 Vulnérabilités DÉPENDANCES détectées : {len(dependency_vulns)}")

# ==========================================================
# Console display
# ==========================================================
if code_vulns:
    print("\n🧠 Code Vulnerabilities (Bandit + NVD):")
    print(tabulate(
        [
            [
                v["cwe"],
                v["file"],
                v["line"],
                v["severity"],
                v["cvss_score"],
                v["issue"]
            ]
            for v in code_vulns
        ],
        headers=["CWE", "File", "Line", "Severity", "CVSS", "Issue"],
        tablefmt="github"
    ))

if dependency_vulns:
    print("\n📦 Dependency Vulnerabilities (Trivy + NVD):")
    print(tabulate(
        [
            [
                v["target"],
                v["package"],
                v["installed_version"],
                v["cve"],
                v["severity"],
                v["cvss_score"]
            ]
            for v in dependency_vulns
        ],
        headers=["Target", "Package", "Version", "CVE", "Severity", "CVSS"],
        tablefmt="github"
    ))

# ==========================================================
# Export unified JSON
# ==========================================================
final_report = {
    "summary": {
        "code_vulnerabilities": len(code_vulns),
        "dependency_vulnerabilities": len(dependency_vulns)
    },
    "code": code_vulns,
    "dependencies": dependency_vulns
}

os.makedirs(os.path.dirname(args.output), exist_ok=True)
with open(args.output, "w") as f:
    json.dump(final_report, f, indent=2)

print(f"\n✅ Rapport sécurité unifié sauvegardé : {args.output}")
