from data_import import load_dataset
from converter import preprocess_dataset
from trainer import train_model, save_model  # trainer.py doit utiliser cloudpickle

if __name__ == "__main__":
    dataset_path = "SMSSpamCollection"  # adapter si local

    # Charger le dataset
    df = load_dataset(dataset_path)

    # Préparer les données
    X_train, X_test, y_train, y_test, vectorizer = preprocess_dataset(df)

    # Entraîner le modèle
    model, accuracy = train_model(X_train, X_test, y_train, y_test)
    print(f"Précision du modèle : {accuracy * 100:.2f}%")

    # Sauvegarder le modèle et le vectorizer
    save_model(model, vectorizer)  # trainer.py doit sauvegarder en cloudpickle
    print("✅ Modèle et vectorizer sauvegardés dans /model")
