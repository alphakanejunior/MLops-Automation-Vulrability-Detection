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
    description="CVE Enrichment for Code (Bandit), Dependencies (Trivy), Models (ModelScan) and Containers (Trivy)"
)
parser.add_argument("--nvd-db", required=True, help="Folder containing NVD 2.0 JSON files")
parser.add_argument("--bandit-report", required=True, help="Bandit report folder or file")
parser.add_argument("--trivy-report", required=True, help="Trivy report folder or file")
parser.add_argument("--modelscan-report", required=True, help="ModelScan report folder or file")
parser.add_argument("--container-reports", required=False, help="Folder containing ContainerScan JSON reports")
parser.add_argument("--output", required=True, help="Output enriched JSON file")
args = parser.parse_args()

# ==========================================================
# Charger NVD 2.0 (index CWE -> CVE)
# ==========================================================
print("🔄 Chargement NVD 2.0 (CWE mapping)…")
nvd_cwe_index = {}
for nvd_file in glob.glob(os.path.join(args.nvd_db, "*.json")):
    with open(nvd_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe = desc["value"].replace("CWE-", "")
                    nvd_cwe_index.setdefault(cwe, []).append(vuln)
print(f"📊 CVE NVD indexées (avec CWE) : {len(nvd_cwe_index)}")

# ==========================================================
# Charger Bandit (CODE)
# ==========================================================
bandit_file = args.bandit_report
if os.path.isdir(bandit_file):
    bandit_file = glob.glob(os.path.join(bandit_file, "*.json"))[0]

with open(bandit_file, "r") as f:
    bandit_data = json.load(f)
bandit_results = bandit_data.get("results", [])
print(f"🔍 Vulnérabilités CODE détectées : {len(bandit_results)}")

# ==========================================================
# Charger Trivy (DEPENDANCES)
# ==========================================================
trivy_file = args.trivy_report
if os.path.isdir(trivy_file):
    trivy_file = glob.glob(os.path.join(trivy_file, "*.json"))[0]

with open(trivy_file, "r") as f:
    trivy_data = json.load(f)

dependency_vulns = []
for result in trivy_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []) or []:
        dependency_vulns.append({
            "type": "dependency",
            "package": vuln.get("PkgName"),
            "version": vuln.get("InstalledVersion"),
            "cve": vuln.get("VulnerabilityID"),
            "severity": vuln.get("Severity"),
            "cvss": vuln.get("CVSS", {}),
            "description": vuln.get("Description") or vuln.get("Title", "")
        })
print(f"📦 Vulnérabilités DÉPENDANCES détectées : {len(dependency_vulns)}")

# ==========================================================
# Charger ModelScan (MODELS)
# ==========================================================
modelscan_file = args.modelscan_report
if os.path.isdir(modelscan_file):
    modelscan_file = glob.glob(os.path.join(modelscan_file, "*.json"))[0]

with open(modelscan_file, "r") as f:
    modelscan_data = json.load(f)

model_vulns = [
    {
        "type": "model",
        "file": v.get("file"),
        "description": v.get("description"),
        "severity": v.get("severity"),
        "tool": v.get("tool", "ModelScan"),
        "cve": v.get("cve"),
        "id": v.get("id")
    }
    for v in modelscan_data.get("vulnerabilities", [])
    if v.get("severity") != "UNKNOWN"
]
print(f"🧪 Vulnérabilités MODELS détectées : {len(model_vulns)}")

# ==========================================================
# Charger ContainerScan (Dockerfiles)
# ==========================================================
container_vulns = []

if args.container_reports and os.path.exists(args.container_reports):
    # Récupération récursive de tous les fichiers JSON Trivy (Dockerfile scan)
    container_files = glob.glob(os.path.join(args.container_reports, "**/*.json"), recursive=True)

    for f in container_files:
        with open(f, "r") as jfile:
            data = json.load(jfile)
            for result in data.get("Results", []):
                target = result.get("Target")  # chemin du Dockerfile
                for vuln in result.get("Misconfigurations", []) or []:
                    container_vulns.append({
                        "type": "container",
                        "dockerfile": target,
                        "vulnerability_id": vuln.get("ID"),
                        "severity": vuln.get("Severity"),
                        "rule": vuln.get("RuleID"),
                        "description": vuln.get("Message"),
                        "tool": "Trivy"
                    })

print(f"🐳 Vulnérabilités DOCKERFILES détectées : {len(container_vulns)}")

# ==========================================================
# Enrichissement CODE (Bandit + NVD)
# ==========================================================
code_vulns = []
for v in bandit_results:
    cwe = str(v.get("issue_cwe", {}).get("id", "N/A"))
    enriched = {
        "type": "code",
        "file": v.get("filename"),
        "line": v.get("line_number"),
        "cwe": cwe,
        "issue": v.get("issue_text"),
        "severity": v.get("issue_severity"),
        "confidence": v.get("issue_confidence"),
        "test_id": v.get("test_id"),
        "source": "Bandit"
    }

    if cwe in nvd_cwe_index:
        cve_item = nvd_cwe_index[cwe][0]["cve"]
        metrics = cve_item.get("metrics", {}).get("cvssMetricV31", [])
        if metrics:
            cvss = metrics[0]["cvssData"]
            enriched.update({
                "mapped_cve": cve_item.get("id"),
                "cvss_score": cvss.get("baseScore"),
                "cvss_vector": cvss.get("vectorString"),
                "nvd_severity": cvss.get("baseSeverity"),
                "source": "Bandit+NVD"
            })
    code_vulns.append(enriched)

# ==========================================================
# Résultat FINAL (JSON)
# ==========================================================
final_report = {
    "summary": {
        "code_issues": len(code_vulns),
        "dependency_issues": len(dependency_vulns),
        "model_issues": len(model_vulns),
        "container_issues": len(container_vulns)
    },
    "code": code_vulns,
    "dependencies": dependency_vulns,
    "models": model_vulns,
    "containers": container_vulns
}

# ==========================================================
# Affichage console
# ==========================================================
if code_vulns:
    print("\n ******************** Rapport_code_vulns ********************")
    print("\n🔐 CODE VULNERABILITIES")
    print(tabulate(
        [[v["file"], v["line"], v.get("mapped_cve",""), v.get("nvd_severity",""), v["issue"]] for v in code_vulns],
        headers=["File", "Line", "CVE", "Severity", "Issue"],
        tablefmt="github"
))
if dependency_vulns:
    print("\n ******************** Rapport_dependency_vulns ********************")
    print("\n📦 DEPENDENCY VULNERABILITIES")
    print(tabulate(
        [[v["package"], v["version"], v["cve"], v["severity"], (v["description"] or "")[:120]] for v in dependency_vulns],
        headers=["Package", "Version", "CVE", "Severity", "Description"],
        tablefmt="github"
))

if model_vulns:
    print("\n ******************** Rapport_model_vulns ********************")
    print("\n🧪 MODEL VULNERABILITIES")
    print(tabulate(
        [[v["file"], v["description"], v["severity"], v["tool"]] for v in model_vulns],
        headers=["File", "Description", "Severity", "Tool"],
        tablefmt="github"
    ))

if container_vulns:
    print("\n ******************** Rapport_container_vulns ********************")
    print("\n🐳 DOCKERFILE VULNERABILITIES")
    print(tabulate(
        [[v["dockerfile"], v["vulnerability_id"], v["severity"], v["rule"], v["description"]] for v in container_vulns],
        headers=["Dockerfile", "VulnID", "Severity", "Rule", "Description"],
        tablefmt="github"
    ))

# ==========================================================
# Export JSON
# ==========================================================
os.makedirs(os.path.dirname(args.output), exist_ok=True)
with open(args.output, "w") as f:
    json.dump(final_report, f, indent=2)

print(f"\n✅ Rapport enrichi généré : {args.output}")
