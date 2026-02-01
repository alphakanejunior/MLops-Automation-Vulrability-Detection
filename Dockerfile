FROM python:3.13-slim

# Installer les dépendances système pour scikit-learn et pandas
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    python3-dev \
    libatlas-base-dev \
    liblapack-dev \
    gfortran \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Créer un utilisateur non-root
RUN useradd -m mluser

WORKDIR /app

# Copier requirements.txt et installer les dépendances
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copier le projet
COPY . .

# Permissions
RUN chown -R mluser:mluser /app
USER mluser

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:80/ || exit 1

CMD ["python", "app.py"]
