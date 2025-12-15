#!/usr/bin/env python3
import json, argparse, re
from pathlib import Path
from tabulate import tabulate

# ==========================================================
# ARGUMENTS
# ==========================================================
parser = argparse.ArgumentParser()
parser.add_argument("--nvd-db", required=True)
parser.add_argument("--bandit-report")
parser.add_argument("--dependency-report")
parser.add_argument("--modelscan-report")
parser.add_argument("--container-reports")
parser.add_argument("--output", required=True)
args = parser.parse_args()

OUTPUT = Path(args.output)
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

# ==========================================================
def load_json(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

# ==========================================================
# EXTRACTION
# ==========================================================
def extract_bandit(r):
    out=[]
    for i in r.get("results",[]):
        out+=re.findall(r"CVE-\d{4}-\d+",i.get("issue_text",""))
        if not out and i.get("issue_cwe"):
            out.append(f"CWE-{i['issue_cwe']['id']}")
    return out

def extract_trivy(r):
    out=[]
    for res in r.get("Results",[]):
        for v in res.get("Vulnerabilities",[]):
            out.append(v.get("VulnerabilityID"))
        for m in res.get("Misconfigurations",[]):
            out.append(m.get("AVDID"))
    return out

# ==========================================================
# LOAD NVD 2.0
# ==========================================================
print("🔄 Chargement NVD 2.0…")
nvd={}

for f in Path(args.nvd_db).glob("*.json"):
    data=load_json(f)
    for item in data.get("vulnerabilities",[]):
        cve=item["cve"]
        cid=cve["id"]

        desc=next((d["value"] for d in cve["descriptions"] if d["lang"]=="en"),"")

        metrics=item.get("metrics",{})
        score=sev=expl=vector=""

        def parse(m):
            return (
                m["cvssData"].get("baseScore",""),
                m["cvssData"].get("baseSeverity",""),
                m.get("exploitabilityScore",""),
                m["cvssData"].get("vectorString","")
            )

        if "cvssMetricV31" in metrics:
            score,sev,expl,vector=parse(metrics["cvssMetricV31"][0])
        elif "cvssMetricV30" in metrics:
            score,sev,expl,vector=parse(metrics["cvssMetricV30"][0])
        elif "cvssMetricV2" in metrics:
            m=metrics["cvssMetricV2"][0]
            score=m["cvssData"].get("baseScore","")
            sev=m.get("severity","")
            expl=m.get("exploitabilityScore","")

        nvd[cid]={
            "description":desc,
            "cvss_score":score,
            "severity":sev,
            "exploitability":expl,
            "vector":vector,
            "references":[r["url"] for r in cve.get("references",[])],
            "source":"NVD"
        }

print(f"📊 CVE chargées : {len(nvd)}")

# ==========================================================
# COLLECT
# ==========================================================
allv=set()

def add(p,fn):
    if not p: return
    p=Path(p)
    if p.is_file():
        allv.update(fn(load_json(p)))
    else:
        for f in p.glob("**/*.json"):
            allv.update(fn(load_json(f)))

add(args.bandit_report,extract_bandit)
add(args.container_reports,extract_trivy)

print(f"🔍 Total vulnérabilités détectées : {len(allv)}")

# ==========================================================
# ENRICH
# ==========================================================
out={}
for v in allv:
    out[v]=nvd.get(v,{
        "description":"",
        "cvss_score":"",
        "severity":"",
        "exploitability":"",
        "vector":"",
        "source":"ReportOnly"
    })

with open(OUTPUT,"w",encoding="utf-8") as f:
    json.dump(out,f,indent=2)

# ==========================================================
# TABLE
# ==========================================================
print("\nVulnerability Enriched Report:\n")
print(tabulate(
    [[k,v["severity"],v["cvss_score"],v["exploitability"],v["source"],v["description"][:90]]
     for k,v in out.items()],
    headers=["ID","Severity","CVSS","Exploitability","Source","Description"],
    tablefmt="grid"
))
