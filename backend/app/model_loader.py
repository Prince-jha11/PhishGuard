
import pickle
from pathlib import Path

def load_model():
    BASE_DIR = Path(__file__).resolve().parent.parent
    MODEL_PATH = BASE_DIR / "model" / "phishing.pkl"

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found at: {MODEL_PATH}"
        )

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    return model
