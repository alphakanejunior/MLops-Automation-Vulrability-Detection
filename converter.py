from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import pandas as pd


def preprocess_dataset(df: pd.DataFrame):
    """
    Prépare le dataset :
    - convertit les labels
    - split train / test
    - vectorise le texte
    """
    df = df.copy()
    df["label"] = df["label"].map({"ham": 0, "spam": 1})

    X_text = df["message"]
    y = df["label"]

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text,
        y,
        test_size=0.2,
        random_state=42
    )

    vectorizer = CountVectorizer()
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    return X_train, X_test, y_train, y_test, vectorizer
