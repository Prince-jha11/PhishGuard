
import pickle
from pathlib import Path

def load_model():
    BASE_DIR = Path(__file__).resolve().parent.parent
    MODEL_PATH = BASE_DIR / "model" / "phishing.pkl"

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Phishing model not found at: {MODEL_PATH}"
        )

    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)
