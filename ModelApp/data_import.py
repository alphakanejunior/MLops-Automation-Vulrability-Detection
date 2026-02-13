import pandas as pd


def load_dataset(path: str) -> pd.DataFrame:
    """
    Charge le dataset SMS Spam Collection.
    """
    return pd.read_csv(
        path,
        sep="\t",
        header=None,
        names=["label", "message"]
    )
