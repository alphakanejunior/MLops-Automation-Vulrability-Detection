from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import joblib
import os


def train_model(X_train, X_test, y_train, y_test):
    """
    Entraîne le modèle Naive Bayes et calcule la précision.
    """
    model = MultinomialNB()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    return model, accuracy


def save_model(model, vectorizer, directory="model"):
    """
    Sauvegarde le modèle et le vectorizer.
    """
    os.makedirs(directory, exist_ok=True)

    joblib.dump(model, f"{directory}/spam_model.pkl")
    joblib.dump(vectorizer, f"{directory}/vectorizer.pkl")
