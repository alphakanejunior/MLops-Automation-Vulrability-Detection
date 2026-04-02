# 🔐 Secure MLOps CI/CD Pipeline

## Automatisation de la gestion des vulnérabilités dans les pipelines MLOps

---

## 📌 Description du projet

Dans un contexte où les applications de Machine Learning sont déployées en production, la sécurité des pipelines MLOps devient essentielle. Contrairement aux applications classiques, les pipelines MLOps introduisent des risques supplémentaires liés aux modèles, aux dépendances et aux environnements d’exécution.

Ce projet met en place un pipeline **CI/CD sécurisé**, basé sur une approche **DevSecOps**, permettant d’automatiser la détection, l’analyse et la gestion des vulnérabilités.

L’objectif est d’intégrer une **prise de décision automatisée (Security Gate)** afin de bloquer tout déploiement contenant des vulnérabilités critiques.

---

## 🎯 Problématique

Dans les pipelines MLOps traditionnels :

* les outils de sécurité sont isolés
* les résultats ne sont pas corrélés
* aucune décision automatique n’est prise

Cela rend la gestion des vulnérabilités inefficace.

👉 Ce projet propose une solution unifiée, automatisée et décisionnelle.

---

## 🧩 Architecture du pipeline

```bash
CodeScan → DependencyScan → ModelScan → ContainerScan → CVEEnrichment → SecurityGate → Deploy → HealthCheck
```

---

## 🔍 Analyse de sécurité multi-couches

Le pipeline implémente une approche multi-niveaux couvrant toutes les surfaces d’attaque.

### 1. Analyse du code (SAST)

Le code Python est analysé avec Bandit afin d’identifier les failles de sécurité et les mauvaises pratiques.

### 2. Analyse des dépendances

Les dépendances sont scannées avec Trivy pour détecter les vulnérabilités connues (CVE).

### 3. Analyse des modèles ML

Les modèles sont analysés avec ModelScan afin de détecter les risques liés à la désérialisation.

### 4. Analyse des conteneurs

Les Dockerfiles sont scannés pour identifier les mauvaises configurations de sécurité.

---

## 🧠 Enrichissement des vulnérabilités

Les résultats des scans sont ensuite corrélés et enrichis via une base locale **NVD**.

Cela permet d’ajouter :

* score CVSS
* niveau de criticité
* informations CVE standardisées

---

## 🚫 Security Gate

Une règle de sécurité est appliquée :

* ❌ présence de vulnérabilité CRITICAL → pipeline bloqué
* ✅ sinon → déploiement autorisé

---

## 🚀 Déploiement sécurisé

Le déploiement est effectué automatiquement via SSH sur une VM, uniquement si le pipeline est validé.

---

## ❤️ Health Check

Après déploiement :

```bash
curl http://<SERVER_IP>/health
```

---

## 📁 Structure du projet

```bash
.
├── .github/workflows/
├── ModelApp/
├── scripts/
├── test/
├── Dockerfile
├── requirements.txt
```

---

# ⚙️ Configuration complète

---

## 🖥 1. Setup du Self-Hosted Runner

Le pipeline s’exécute sur une VM via un runner GitHub self-hosted.

### Installation

```bash
# Créer dossier
mkdir actions-runner && cd actions-runner

# Télécharger
curl -o actions-runner.tar.gz -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz

# Extraire
tar xzf actions-runner.tar.gz

# Configurer
./config.sh --url https://github.com/<OWNER>/<REPO> --token <TOKEN>

# Lancer
./run.sh
```

### Mode service (recommandé)

```bash
sudo ./svc.sh install
sudo ./svc.sh start
```

---

## 🔐 2. Configuration des GitHub Secrets

Dans GitHub :

**Settings → Secrets and variables → Actions**

Ajouter :

```bash
VM_HOST=xxx.xxx.xxx.xxx
VM_USER=azureuser
VM_SSH_KEY=<clé privée>
SERVER_IP=xxx.xxx.xxx.xxx
```

---

## 🔑 Génération clé SSH

```bash
ssh-keygen -t rsa -b 4096
```

```bash
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
```

---

## 🖥 3. Préparation de la VM

### Installation des dépendances

```bash
sudo apt update -y
sudo apt install -y docker.io git curl
```

### Activer Docker

```bash
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

(Reconnexion nécessaire)

---

## 🔍 Installation de Trivy

```bash
sudo apt-get install -y wget apt-transport-https gnupg lsb-release

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -

echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/trivy.list

sudo apt-get update -y
sudo apt-get install -y trivy
```

---

## 🧠 Base NVD locale

```bash
mkdir -p /home/runner/nvd_data
```

---

## 🌐 Ports nécessaires

```bash
# Autoriser ports
sudo ufw allow 22
sudo ufw allow 80
```

---

## 🚀 Déploiement manuel (test)

```bash
# Build image
docker build -t mlapp:latest .

# Run container
docker run -d -p 80:80 mlapp:latest
```

---

## 🔐 Scan sécurité Docker

```bash
trivy image mlapp:latest
```

---

## 📦 Exemple de scan dépendances

```bash
trivy fs .
```

---

## 📊 Résultat final

Ce pipeline permet :

* ✔ détection automatique des vulnérabilités
* ✔ corrélation et enrichissement CVE
* ✔ blocage des risques critiques
* ✔ déploiement sécurisé automatisé

---

## 🧠 Bonnes pratiques appliquées

* DevSecOps
* Shift-left security
* Zero Trust deployment
* Infrastructure as Code security

---

## 🎯 Objectif

Fournir un pipeline :

* sécurisé
* automatisé
* prêt pour production

---

## ⭐ Conclusion

Ce projet représente une implémentation complète d’un pipeline **MLOps sécurisé**, combinant :

* analyse multi-couches
* automatisation CI/CD
* gouvernance sécurité

👉 Une solution robuste adaptée aux environnements professionnels.
