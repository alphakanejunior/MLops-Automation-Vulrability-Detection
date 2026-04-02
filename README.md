🔐 Secure MLOps Pipeline
1 Automated Vulnerability Detection, Enrichment & Governance

This project implements a fully automated DevSecOps pipeline for MLOps environments, designed to ensure that machine learning applications are secure before deployment.

The pipeline integrates multiple security layers to:

Detect vulnerabilities across code, dependencies, models, and containers
Enrich findings using NVD (National Vulnerability Database)
Correlate heterogeneous security results
Enforce security policies automatically
Prevent insecure deployments
Enable secure, traceable CI/CD workflows
🚀 Key Features
🔍 Multi-layer vulnerability scanning
🧠 CVE enrichment using local NVD database
🔗 Cross-tool correlation (Bandit, Trivy, ModelScan)
🚫 Automated Security Gate (fail on critical issues)
🐳 Secure container build & deployment
📊 Versioned security reports
⚙️ Self-hosted runner compatibility
🔁 Fully automated CI/CD pipeline

🏗️ Pipeline Architecture
CodeScan
   ↓
DependencyScan
   ↓
ModelScan
   ↓
ContainerScan
   ↓
CVEEnrichment
   ↓
SecurityGate (main branch only)
   ↓
DeployOnVM
   ↓
HealthCheck
⚙️ Workflow Execution
🔁 Triggers

The pipeline is triggered on:

push to Develop and main
pull_request targeting Develop and main
🔐 Security Stages
1. CodeScan – Static Application Security Testing (SAST)
Tool: Bandit
Scans Python source code for:
Insecure coding practices
Potential vulnerabilities
Outputs structured JSON reports
2. DependencyScan – Open Source Vulnerability Detection
Tool: Trivy (Filesystem mode)
Detects:
Known CVEs in dependencies
Vulnerable package versions
3. ModelScan – ML Model Security
Tool: ModelScan
Identifies:
Unsafe serialization patterns
Model-level vulnerabilities
Converts output into normalized JSON format
4. ContainerScan – Infrastructure as Code Security
Tool: Trivy Config
Scans Dockerfiles for:
Misconfigurations
Security anti-patterns
Hardcoded secrets
Unsafe permissions
5. CVEEnrichment – Centralized Intelligence Layer

This stage is the core of the pipeline.

Responsibilities:
Aggregate all scan results
Normalize heterogeneous formats
Enrich vulnerabilities using local NVD database
Assign severity and context
Generate a unified report
Output:
reports/cve_enrichment/<run_id>/enriched_cves.json
🚫 Security Gate Policy

Executed only on main branch

The pipeline enforces a strict security rule:

❌ Any CRITICAL vulnerability blocks deployment

Evaluated Domains:
Source code vulnerabilities
Dependency CVEs
ML model issues
Container misconfigurations
Result:
✅ No critical issues → Deployment allowed
❌ Critical issues found → Pipeline fails
🚀 Deployment Strategy

Deployment is performed on an Azure Virtual Machine via SSH.

Steps:
Repository synchronization
Docker image build
Container image vulnerability scan (Trivy)
Deployment condition:
No CRITICAL vulnerabilities
Container restart
Application exposure on port 80
❤️ Health Check

Post-deployment validation:

GET /health
Ensures service availability
Fails pipeline if unreachable
📊 Reports & Traceability

Each pipeline run is uniquely identified using:

TIMESTAMP = github.run_id
Generated Reports:
Stage	Output Path
Bandit	reports/bandit/<id>/
Trivy (deps)	reports/dependency/<id>/
ModelScan	reports/models/<id>/
ContainerScan	reports/container/<id>/
CVE Enrichment	reports/cve_enrichment/<id>/

✔️ Enables:

Auditability
Historical tracking
Security compliance
🧰 Prerequisites
Self-Hosted Runner
Linux (x64)
Python 3.11
Docker
Trivy installed (or installable)
Access to local NVD database:
/home/runner/nvd_data
🔐 Configuration
Required GitHub Secrets
VM_HOST
VM_USER
VM_SSH_KEY
SERVER_IP
📁 Project Structure
.
├── .github/workflows/
│   └── pipeline.yml
├── scripts/
│   └── cve_enrichment.py
├── ModelApp/
│   └── model/
├── reports/
└── README.md
🔮 Future Improvements
📊 Security dashboards (Grafana / Kibana)
📈 Risk scoring engine
📩 Alerting system (Slack, Email)
🧠 AI-based vulnerability prioritization
🔄 Continuous compliance checks
🎯 Conclusion

This project demonstrates how to transform a traditional CI/CD pipeline into a secure, intelligent, and decision-driven MLOps pipeline.