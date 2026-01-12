from data_import import load_dataset
from converter import preprocess_dataset
from trainer import train_model, save_model


if __name__ == "__main__":
    dataset_path = "SMSSpamCollection"  # adapter si local

    df = load_dataset(dataset_path)
    X_train, X_test, y_train, y_test, vectorizer = preprocess_dataset(df)

    model, accuracy = train_model(X_train, X_test, y_train, y_test)
    print(f"Précision du modèle : {accuracy * 100:.2f}%")

    save_model(model, vectorizer)
    print("✅ Modèle et vectorizer sauvegardés dans /model")
