import pandas as pd
import numpy as np
import joblib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models"

# LOAD MODELS

preprocessor = joblib.load(
    MODEL_PATH / "preprocessor.pkl"
)

classifier = joblib.load(
    MODEL_PATH / "threat_classifier.pkl"
)

anomaly_detector = joblib.load(
    MODEL_PATH / "anomaly_detector.pkl"
)


# THREAT DETECTION FUNCTION


def detect_threat(data):

    processed_data = preprocessor.transform(data)

    
    # SUPERVISED MODEL
    

    attack_probability = classifier.predict_proba(
        processed_data
    )[:, 1]


    
    # ANOMALY MODEL
    

    anomaly_prediction = anomaly_detector.predict(
        processed_data
    )

    anomaly_score_raw = anomaly_detector.decision_function(
        processed_data
    )


    # Convert anomaly result into 0-1 score
    anomaly_score = 1 / (
        1 + np.exp(anomaly_score_raw)
    )


    
    # HYBRID RISK SCORE
    

    risk_score = (
        0.65 * attack_probability
        +
        0.35 * anomaly_score
    )


    
    # STATUS
  

    status = []

    for score in risk_score:

        if score < 0.35:
            status.append("NORMAL")

        elif score < 0.70:
            status.append("SUSPICIOUS")

        else:
            status.append("HIGH RISK")


    
    # OUTPUT
    

    results = data.copy()

    results["attack_probability"] = (
        attack_probability
    )

    results["anomaly_score"] = (
        anomaly_score
    )

    results["risk_score"] = (
        risk_score
    )

    results["status"] = status


    return results