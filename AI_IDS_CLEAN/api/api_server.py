import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

# -----------------------------
# Load Model & Scaler
# -----------------------------
print("Loading model and scaler...")

model = joblib.load("models/model.pkl")
scaler = joblib.load("models/scaler.pkl")

print("Model loaded successfully.")

# -----------------------------
# FastAPI App
# -----------------------------
app = FastAPI(
    title="AI-Powered IDS API",
    description="Real-time Network Intrusion Detection",
    version="1.0"
)

# -----------------------------
# Input Schema
# -----------------------------
class FlowInput(BaseModel):
    features: list  # list of 10 numeric features

# -----------------------------
# Home Route
# -----------------------------
@app.get("/")
def home():
    return {"message": "AI-IDS API is running successfully"}

# -----------------------------
# Prediction Route
# -----------------------------
@app.post("/predict")
def predict(input_data: FlowInput):
    try:
        features = np.array(input_data.features).reshape(1, -1)

        # Scale input
        features_scaled = scaler.transform(features)

        # Predict
        prediction = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0][1]

        label = "BENIGN" if prediction == 0 else "MALICIOUS"

        return {
            "prediction": int(prediction),
            "result": label,
            "malicious_probability": float(probability)
        }

    except Exception as e:
        return {"error": str(e)}