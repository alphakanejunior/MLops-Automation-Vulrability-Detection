import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from trainer import train_model, save_model
from sklearn.naive_bayes import MultinomialNB

# Charger les données
df = pd.read_csv("SMSSpamCollection", sep='\t', header=None, names=['label', 'message'])
df['label'] = df['label'].map({'ham': 0, 'spam': 1})

# Convertir les messages en vecteurs
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(df['message'])
y = df['label']

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Entraîner le modèle
model, accuracy = train_model(X_train, X_test, y_train, y_test)
print(f"Accuracy: {accuracy:.4f}")

# Sauvegarder modèle et vectorizer
save_model(model, vectorizer)
print("Modèle et vectorizer sauvegardés dans ./model/")

