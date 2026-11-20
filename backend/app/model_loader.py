import os
import pickle

def load_model():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(base_dir, "model", "phishing.pkl")
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    return model
