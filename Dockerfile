# Utiliser Python 3.12 slim comme base
FROM python:3.12-slim

# Créer un utilisateur non-root
RUN useradd -m mluser

# Définir le répertoire de travail
WORKDIR /app

# Copier requirements.txt et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le code dans l'image
COPY . .

# Définir les permissions
RUN chown -R mluser:mluser /app
USER mluser

# Exposer le port de l'application
EXPOSE 80

# Healthcheck sur le port 80
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:5000/ || exit 1

# Définir la commande par défaut
CMD ["python3", "ModelApp/app.py"]