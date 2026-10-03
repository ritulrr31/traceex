import pandas as pd
import numpy as np
import joblib
import os

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score
)

from preprocessing import create_preprocessor


DATA_PATH = "../data/network_flows.csv"
MODEL_PATH = "../models"


# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

df = pd.read_csv(DATA_PATH)

print("\nDataset loaded")
print("Shape:", df.shape)
print(df.head())


# --------------------------------------------------
# TARGET
# --------------------------------------------------

if "label" not in df.columns:
    raise ValueError(
        "Dataset must contain a 'label' column."
    )

X = df.drop(columns=["label"])
y = df["label"]


# Convert labels to 0 and 1 if necessary
if y.dtype == "object":

    y = y.astype(str).str.lower()

    y = y.map({
        "normal": 0,
        "benign": 0,
        "attack": 1,
        "malicious": 1,
        "threat": 1
    })

    if y.isna().any():
        raise ValueError(
            "Unknown values found in label column."
        )


# --------------------------------------------------
# TRAIN / TEST SPLIT
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# --------------------------------------------------
# PREPROCESSING
# --------------------------------------------------

preprocessor = create_preprocessor()

X_train_processed = preprocessor.fit_transform(X_train)
X_test_processed = preprocessor.transform(X_test)


# --------------------------------------------------
# RANDOM FOREST
# --------------------------------------------------

print("\nTraining Random Forest...")

classifier = RandomForestClassifier(
    n_estimators=250,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

classifier.fit(
    X_train_processed,
    y_train
)


# --------------------------------------------------
# CLASSIFICATION RESULTS
# --------------------------------------------------

predictions = classifier.predict(X_test_processed)

probabilities = classifier.predict_proba(
    X_test_processed
)[:, 1]


print("\n==============================")
print("RANDOM FOREST RESULTS")
print("==============================")

print(
    classification_report(
        y_test,
        predictions
    )
)

print("Accuracy:",
      accuracy_score(y_test, predictions))

try:

    print(
        "ROC-AUC:",
        roc_auc_score(
            y_test,
            probabilities
        )
    )

except Exception:
    pass


print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# --------------------------------------------------
# ISOLATION FOREST
# --------------------------------------------------

print("\nTraining Isolation Forest...")

anomaly_detector = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42
)

anomaly_detector.fit(
    X_train_processed
)


# --------------------------------------------------
# SAVE MODELS
# --------------------------------------------------

os.makedirs(
    MODEL_PATH,
    exist_ok=True
)

joblib.dump(
    preprocessor,
    MODEL_PATH + "/preprocessor.pkl"
)

joblib.dump(
    classifier,
    MODEL_PATH + "/threat_classifier.pkl"
)

joblib.dump(
    anomaly_detector,
    MODEL_PATH + "/anomaly_detector.pkl"
)


print("\nModels saved successfully.")

print(
    "\nFiles created:"
)

print("models/preprocessor.pkl")
print("models/threat_classifier.pkl")
print("models/anomaly_detector.pkl")