# 📩 Spam Detector – Machine Learning API with Flask & Docker

[![Python](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Container-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

---

## 🔹 Description

**Spam Detector** est une application web permettant de détecter automatiquement les messages SPAM et HAM à partir de SMS.  
Le projet combine **Machine Learning**, **API Flask**, et **Docker**, avec un frontend moderne et responsive.  

Fonctionnalités principales :
- Détection de messages SPAM / HAM via un modèle Naive Bayes
- API REST pour prédictions
- Frontend web interactif
- Container Docker prêt à l’emploi
- Architecture modulaire pour tests et améliorations

---

## 🧱 Architecture du projet

project/
│
├── app.py # API Flask + Frontend
├── data_import.py # Chargement du dataset
├── converter.py # Préprocessing + vectorisation
├── trainer.py # Entraînement + sauvegarde du modèle
├── main.py # Script d'entraînement
├── test.py # Test des prédictions
│
├── model/
│ ├── spam_model.pkl
│ └── vectorizer.pkl
├── templates/
│ └── index.html # Frontend
├── static/
│ └── style.css
├── requirements.txt
├── Dockerfile
└── README.md

---

## 📂 Dataset

Le projet utilise le dataset **SMS Spam Collection**.  
- `ham` → messages normaux  
- `spam` → messages frauduleux ou publicitaires  

Le fichier `SMSSpamCollection` doit être placé à la racine du projet.

---

## 🧠 Entraînement du modèle

Avant de lancer l’API ou Docker, il faut entraîner le modèle :  

```bash
python main.py
Cela génère automatiquement :

model/spam_model.pkl

model/vectorizer.pkl

🌐 Lancer l’API Flask (local)

python app.py
Puis ouvrir :

http://localhost:5000
Champ texte pour entrer un message

Bouton Predict

Résultat affiché : SPAM ❌ / HAM ✅

🐳 Dockerisation
Build de l’image
docker build -t spam-api .

Lancer le container
docker run -p 5000:5000 spam-api

🎨 Frontend
Modern, responsive avec Bootstrap 5

Champ texte et bouton prédiction

Couleurs intuitives :

🔴 SPAM

🟢 HAM

Possibilité de tester rapidement différents messages

🛠️ Technologies utilisées
Python 3.10

Flask

scikit-learn

pandas / numpy

Docker

Bootstrap 5