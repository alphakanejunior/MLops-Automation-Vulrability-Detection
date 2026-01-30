import joblib


def load_artifacts(
    model_path="model/spam_model.pkl",
    vectorizer_path="model/vectorizer.pkl"
):
    """
    Charge le modèle et le vectorizer entraînés.
    """
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    return model, vectorizer


def predict_spam(message: str, model, vectorizer) -> str:
    """
    Prédit si un message est un spam ou non.
    """
    message_vectorized = vectorizer.transform([message])
    prediction = model.predict(message_vectorized)[0]

    return "SPAM ❌" if prediction == 1 else "HAM ✅"


if __name__ == "__main__":
    model, vectorizer = load_artifacts()

    print(predict_spam("Hey, well ? Ready for competition ?", model, vectorizer))
    print(
        predict_spam(
            "Hey, you have winning cup. Give your account bank detail to keep your prize !",
            model,
            vectorizer
        )
    )
