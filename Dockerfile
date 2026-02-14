# =============================================================
# Dockerfile pour MLops-Automation-Vuln-Detection
# =============================================================

# 1️ Base Python slim
FROM python:3.12-slim

# 2️ Créer un utilisateur non-root
RUN useradd -m mluser

# 3️ Définir le répertoire de travail
WORKDIR /app

# 4️ Copier requirements et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5️ Copier tout le projet
COPY . .

# 6️ Vérifier que le dossier model existe
RUN mkdir -p /app/ModelApp/model

# 7️ Changer les droits sur les fichiers pour mluser
RUN chown -R mluser:mluser /app
USER mluser

# 8️ Exposer le port Flask
EXPOSE 80

# 9️ Lancer l'application Flask
CMD ["python3", "ModelApp/app.py"]
