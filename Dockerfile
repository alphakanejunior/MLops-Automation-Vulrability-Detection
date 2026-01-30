# Utiliser Python 3.13 slim comme base
FROM python:3.13-slim

# Créer un utilisateur non-root
RUN useradd -m mluser

# Définir le répertoire de travail
WORKDIR /app

# Copier le fichier requirements.txt et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    scikit-learn==1.7.2 \
    joblib==1.5.2 \
    flask \
    pandas \
    numpy

# Copier tout le projet
COPY . .

# Définir les permissions
RUN chown -R mluser:mluser /app
USER mluser

# Exposer le port 80
EXPOSE 80

# Healthcheck sur le port 80
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:80/ || exit 1

# Commande pour démarrer l'application
CMD ["python", "app.py"]
