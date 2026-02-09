# Utiliser Python 3.13 slim comme base
FROM python:3.12-slim

# Créer un utilisateur non-root
RUN useradd -m mluser

# Définir le répertoire de travail
WORKDIR /app

# Copier le fichier requirements.txt et installer les dépendances.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 

# Entraîner le modèle (créera le fichier model.pkl ou similaire)
RUN python train_model.py
# Copier tout le projet
COPY . .

# Définir les permissions
RUN chown -R mluser:mluser /app
USER mluser

# Exposer le port 80
EXPOSE 80

# Healthcheck sur le port 80
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:5000/ || exit 1
 
# Commande pour démarrer l'application
CMD ["python", "app.py"]

