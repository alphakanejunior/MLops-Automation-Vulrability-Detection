#!/usr/bin/env python3
"""
cve_enrichment.py
Enrichissement complet des vulnérabilités :
- CVE -> NVD 2.0
- PYSEC -> OSV.dev
- AVD -> Trivy
- CWE -> Sévérité estimée
"""

import json
import argparse
import re
import glob
import requests
from pathlib import Path
from tabulate import tabulate

# ==========================================================
# ARGUMENTS CLI
# ==========================================================
parser = argparse.ArgumentParser(description="CVE Enrichment Tool (FINAL)")
parser.add_argument("--nvd-db", required=True, help="Dossier NVD JSON 2.0")
parser.add_argument("--bandit-report", required=False)
parser.add_argument("--dependency-report", required=False)
parser.add_argument("--modelscan-report", required=False)
parser.add_argument("--container-reports", required=False)
parser.add_argument("--output", required=True)
args = parser.parse_args()

OUTPUT = Path(args.output)
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

# ==========================================================
# UTILS
# ==========================================================
def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

# ==========================================================
# CWE SEVERITY MAP (ESTIMÉ)
# ==========================================================
CWE_SEVERITY = {
    "CWE-89": ("CRITICAL", 9.8),
    "CWE-78": ("CRITICAL", 9.5),
    "CWE-502": ("HIGH", 8.5),
    "CWE-259": ("HIGH", 7.5),
    "CWE-20": ("MEDIUM", 6.5),
    "CWE-605": ("MEDIUM", 6.0),
}

# ==========================================================
# EXTRACTORS
# ==========================================================
def extract_bandit(report):
    ids = set()
    for r in report.get("results", []):
        ids.update(re.findall(r"CVE-\d{4}-\d{4,7}", r.get("issue_text", "")))
        cwe = r.get("issue_cwe", {}).get("id")
        if cwe:
            ids.add(f"CWE-{cwe}")
    return ids

def extract_dependency(report):
    ids = set()
    for d in report.get("dependencies", []):
        for v in d.get("vulns", []):
            ids.add(v.get("id"))
    return ids

def extract_modelscan(report):
    return {v.get("cve") for v in report.get("vulnerabilities", []) if v.get("cve")}

def extract_trivy(report):
    ids = set()
    for r in report.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            ids.add(v.get("VulnerabilityID"))
        for m in r.get("Misconfigurations", []):
            ids.add(m.get("AVDID"))
    return ids

# ==========================================================
# LOAD NVD 2.0
# ==========================================================
print("🔄 Chargement NVD 2.0…")
nvd_data = {}

for file in Path(args.nvd_db).glob("*.json"):
    data = load_json(file)
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")

        metrics = item.get("metrics", {})
        cvss = {}
        severity = ""
        exploit = ""

        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss = m.get("cvssData", {})
            severity = cvss.get("baseSeverity", "")
            exploit = m.get("exploitabilityScore", "")

        nvd_data[cve_id] = {
            "description": desc,
            "cvss_v3_score": cvss.get("baseScore", ""),
            "cvss_vector": cvss.get("vectorString", ""),
            "severity": severity,
            "exploitability": exploit,
            "references": [r["url"] for r in cve.get("references", [])],
            "patch": "",
            "source": "NVD"
        }

print(f"📊 CVE NVD chargées : {len(nvd_data)}")

# ==========================================================
# COLLECT ALL IDS
# ==========================================================
all_ids = set()

def collect(path, extractor):
    p = Path(path)
    if p.is_file():
        all_ids.update(extractor(load_json(p)))
    elif p.is_dir():
        for f in p.glob("**/*.json"):
            all_ids.update(extractor(load_json(f)))

if args.bandit_report:
    collect(args.bandit_report, extract_bandit)
if args.dependency_report:
    collect(args.dependency_report, extract_dependency)
if args.modelscan_report:
    collect(args.modelscan_report, extract_modelscan)
if args.container_reports:
    for f in glob.glob(args.container_reports, recursive=True):
        all_ids.update(extract_trivy(load_json(f)))

print(f"🔍 Vulnérabilités détectées : {len(all_ids)}")

# ==========================================================
# OSV (PYSEC)
# ==========================================================
def enrich_pysec(pysec_id):
    r = requests.post(
        "https://api.osv.dev/v1/query",
        json={"query": pysec_id},
        timeout=10
    )
    if r.status_code != 200:
        return None

    v = r.json().get("vulns", [])
    if not v:
        return None

    vuln = v[0]
    sev = vuln.get("severity", [{}])
    score = sev[0].get("score", "")

    return {
        "description": vuln.get("summary", ""),
        "cvss_v3_score": score,
        "severity": sev[0].get("type", ""),
        "exploitability": "",
        "patch": vuln.get("references", [{}])[0].get("url", ""),
        "source": "OSV"
    }

# ==========================================================
# ENRICH
# ==========================================================
enriched = {}

for vid in sorted(all_ids):
    if vid in nvd_data:
        enriched[vid] = nvd_data[vid]

    elif vid.startswith("PYSEC"):
        osv = enrich_pysec(vid)
        enriched[vid] = osv if osv else {
            "description": "",
            "cvss_v3_score": "",
            "severity": "",
            "exploitability": "",
            "patch": "",
            "source": "PYSEC"
        }

    elif vid.startswith("CWE"):
        sev, score = CWE_SEVERITY.get(vid, ("LOW", 3.0))
        enriched[vid] = {
            "description": "Faiblesse de sécurité (CWE)",
            "cvss_v3_score": score,
            "severity": sev,
            "exploitability": "",
            "patch": "Correction du code requise",
            "source": "CWE"
        }

    else:
        enriched[vid] = {
            "description": "",
            "cvss_v3_score": "",
            "severity": "",
            "exploitability": "",
            "patch": "",
            "source": "ReportOnly"
        }

# ==========================================================
# SAVE
# ==========================================================
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(enriched, f, indent=2)

print(f"✅ Rapport enrichi sauvegardé : {OUTPUT}")

# ==========================================================
# TABLE
# ==========================================================
table = [
    [
        v,
        i.get("severity", ""),
        i.get("cvss_v3_score", ""),
        i.get("exploitability", ""),
        i.get("source", ""),
        i.get("description", "")[:80]
    ]
    for v, i in enriched.items()
]

print(tabulate(
    table,
    headers=["ID", "Severity", "CVSSv3", "Exploitability", "Source", "Description"],
    tablefmt="grid"
))
