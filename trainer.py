from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import joblib
import cloudpickle
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
    Sauvegarde le modèle avec cloudpickle (portable Linux) 
    et le vectorizer avec joblib.
    """
    os.makedirs(directory, exist_ok=True)

    # Modèle avec cloudpickle
    model_path = os.path.join(directory, "spam_model_cp.pkl")
    with open(model_path, "wb") as f:
        cloudpickle.dump(model, f)

    # Vectorizer reste en joblib
    vectorizer_path = os.path.join(directory, "vectorizer.pkl")
    joblib.dump(vectorizer, vectorizer_path)

    print(f"✅ Modèle sauvegardé : {model_path}")
    print(f"✅ Vectorizer sauvegardé : {vectorizer_path}")
