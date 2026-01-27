FROM python:3.10-slim

# Créer un utilisateur non-root
RUN useradd -m mluser

WORKDIR /app

# Copier les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le projet
COPY . .

# Basculer vers utilisateur non privilégié
USER mluser

# Exposer le port Flask
EXPOSE 5000

# Vérifier que l’API répond
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:5000/ || exit 1

# Lancer l’API
CMD ["python", "app.py"]
