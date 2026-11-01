
from pathlib import Path
from io import BytesIO

import joblib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# --------------------------------------------------
# PROJECT PATHS AND CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(r"D:\MLPROJECt1")
MODEL_DIR = BASE_DIR / "models"
BASELINE_PATH = BASE_DIR / "data" / "traffic_ingress_feed.csv"

FEATURES = [
    "packet_rate",
    "src_ip_entropy",
    "iat_variance",
    "outbound_bytes_ratio",
    "payload_entropy",
    "dst_port_diversity",
    "avg_packet_size",
    "burst_density_ratio",
]

CLASS_NAMES = {
    0: "Normal",
    1: "DDoS",
    2: "Botnet C2",
    3: "Data Exfiltration",
}

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]


# --------------------------------------------------
# AUTOENCODER ARCHITECTURE
# --------------------------------------------------

class ExfilAutoencoder8D(nn.Module):

    def __init__(self):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(8, 4),
            nn.ReLU()
        )

        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="TracX API",
    description="Passive network threat monitoring API",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# MODEL VARIABLES
# --------------------------------------------------

ddos_model = None
botnet_model = None
exfil_model = None

scaling_min = None
scaling_max = None

model_errors = {}


# --------------------------------------------------
# LOAD TRAINED MODELS
# --------------------------------------------------

@app.on_event("startup")
def load_models():

    global ddos_model, botnet_model
    global exfil_model, scaling_min, scaling_max

    print("BASE_DIR:", BASE_DIR)
    print("MODEL_DIR:", MODEL_DIR)

    # Isolation Forest
    try:
        ddos_model = joblib.load(
            MODEL_DIR / "ddos_forest.pkl"
        )
        print("Isolation Forest loaded.")

    except Exception as exc:
        model_errors["ddos_forest"] = str(exc)

    # XGBoost
    try:
        botnet_model = joblib.load(
            MODEL_DIR / "botnet_xgb.pkl"
        )
        print("XGBoost loaded.")

    except Exception as exc:
        model_errors["botnet_xgb"] = str(exc)

    # PyTorch Autoencoder
    try:
        exfil_model = ExfilAutoencoder8D()

        state_dict = torch.load(
            MODEL_DIR / "exfil_autoencoder.pth",
            map_location="cpu"
        )

        exfil_model.load_state_dict(state_dict)
        exfil_model.eval()

        scaling_data = np.load(
            MODEL_DIR / "scaling_params.npz"
        )

        scaling_min = scaling_data["min"]
        scaling_max = scaling_data["max"]

        print("PyTorch Autoencoder loaded.")

    except Exception as exc:
        exfil_model = None
        model_errors["exfil_autoencoder"] = str(exc)


# --------------------------------------------------
# SEVERITY BASELINE AND CALCULATION
# --------------------------------------------------

def calculate_traffic_severity(feature_data):

    if not BASELINE_PATH.exists():
        raise ValueError(
            f"Severity baseline not found: {BASELINE_PATH}"
        )

    baseline_df = pd.read_csv(BASELINE_PATH)

    if "label" not in baseline_df.columns:
        raise ValueError(
            "Baseline CSV must contain a label column."
        )

    normal_data = baseline_df.loc[
        pd.to_numeric(
            baseline_df["label"], errors="coerce"
        ) == 0,
        FEATURES
    ].copy()

    normal_data = normal_data.apply(
        pd.to_numeric, errors="coerce"
    ).dropna()

    if len(normal_data) < 100:
        raise ValueError(
            "Not enough normal records for severity baseline."
        )

    reference = normal_data.to_numpy(dtype=float)

    incoming = feature_data[FEATURES].to_numpy(
        dtype=float
    )

    # Calculate median and robust feature scales.
    median = np.median(reference, axis=0)

    mad = np.median(
        np.abs(reference - median),
        axis=0
    )

    q75 = np.percentile(reference, 75, axis=0)
    q25 = np.percentile(reference, 25, axis=0)

    iqr_scale = (q75 - q25) / 1.349

    std_scale = np.std(reference, axis=0)

    scale = np.where(
        mad > 1e-10,
        1.4826 * mad,
        np.where(
            iqr_scale > 1e-10,
            iqr_scale,
            std_scale
        )
    )

    scale = np.where(
        scale > 1e-10,
        scale,
        1.0
    )

    # Baseline deviations.
    baseline_z = np.abs(
        (reference - median) / scale
    )

    baseline_raw_scores = np.mean(
        np.sort(baseline_z, axis=1)[:, -3:],
        axis=1
    )

    # Incoming traffic deviations.
    incoming_z = np.abs(
        (incoming - median) / scale
    )

    incoming_raw_scores = np.mean(
        np.sort(incoming_z, axis=1)[:, -3:],
        axis=1
    )

    # Percentile-based traffic risk scores.
    sorted_scores = np.sort(
        baseline_raw_scores
    )

    ranks = np.searchsorted(
        sorted_scores,
        incoming_raw_scores,
        side="right"
    )

    risk_scores = (
        100.0 * ranks / len(sorted_scores)
    )

    # Provisional severity thresholds.
    severity_categories = np.select(
        [
            risk_scores >= 99.9,
            risk_scores >= 99.0,
            risk_scores >= 95.0,
        ],
        [
            "Critical",
            "High",
            "Medium",
        ],
        default="Low"
    )

    return risk_scores, severity_categories


# --------------------------------------------------
# INPUT VALIDATION MODEL
# --------------------------------------------------

class FlowInput(BaseModel):

    packet_rate: float = Field(ge=0)
    src_ip_entropy: float = Field(ge=0)
    iat_variance: float = Field(ge=0)
    outbound_bytes_ratio: float = Field(ge=0)
    payload_entropy: float = Field(ge=0)
    dst_port_diversity: float = Field(ge=0)
    avg_packet_size: float = Field(ge=0)
    burst_density_ratio: float = Field(ge=0)


# --------------------------------------------------
# ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "project": "TracX",
        "status": "running"
    }


# --------------------------------------------------
# HEALTH ENDPOINT
# --------------------------------------------------

@app.get("/api/health")
def health():

    return {
        "status": "healthy",

        "models_loaded": {
            "ddos_forest": ddos_model is not None,
            "botnet_xgb": botnet_model is not None,
            "exfil_autoencoder": exfil_model is not None,
        },

        "model_errors": model_errors,
    }


# --------------------------------------------------
# SINGLE FLOW PREDICTION
# --------------------------------------------------

@app.post("/api/predict")
def predict(flow: FlowInput):

    if (
        ddos_model is None
        or botnet_model is None
        or exfil_model is None
    ):
        raise HTTPException(
            status_code=503,
            detail={
                "message": "One or more models failed to load.",
                "model_errors": model_errors,
            }
        )

    row = pd.DataFrame(
        [[getattr(flow, feature) for feature in FEATURES]],
        columns=FEATURES,
    )

    try:

        # Isolation Forest
        ddos_result = int(
            ddos_model.predict(row)[0]
        )

        ddos_score = float(
            ddos_model.decision_function(row)[0]
        )

        # XGBoost
        class_id = int(
            botnet_model.predict(row)[0]
        )

        probabilities = botnet_model.predict_proba(row)[0]

        probability_results = {
            CLASS_NAMES.get(int(class_id), str(class_id)): float(prob)
            for class_id, prob in zip(
                botnet_model.classes_,
                probabilities
            )
        }

        detection_confidence = float(
            np.max(probabilities) * 100
        )

        # Autoencoder
        input_array = row[FEATURES].values.astype(
            np.float32
        )

        scaled_input = (
            (input_array - scaling_min)
            / (scaling_max - scaling_min + 1e-8)
        )

        tensor_input = torch.tensor(
            scaled_input,
            dtype=torch.float32
        )

        with torch.no_grad():

            reconstructed = exfil_model(
                tensor_input
            )

            reconstruction_error = torch.mean(
                (reconstructed - tensor_input) ** 2
            ).item()

        # Severity
        severity_scores, severity_categories = (
            calculate_traffic_severity(row)
        )

        return {

            "ddos_anomaly": ddos_result == -1,

            "ddos_anomaly_score": ddos_score,

            "predicted_class_id": class_id,

            "predicted_class": CLASS_NAMES.get(
                class_id,
                f"Unknown class {class_id}"
            ),

            "class_probabilities": probability_results,

            "detection_confidence": detection_confidence,

            "severity_score": float(severity_scores[0]),

            "severity": str(severity_categories[0]),

            "exfil_reconstruction_error": float(
                reconstruction_error
            ),

            "exfil_threshold_configured": False,

            "exfil_status": (
                "Score only - threshold not calibrated"
            ),

            "input_features": row.iloc[0].to_dict(),

            "note": (
                "Models were trained on synthetic data. "
                "Severity is a provisional baseline-relative "
                "traffic-risk score, not confirmed incident impact. "
                "Detection confidence is model confidence, not accuracy. "
                "Validate on representative ICS/SCADA traffic."
            )
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {exc}"
        ) from exc


# --------------------------------------------------
# CSV ANALYSIS ENDPOINT
# --------------------------------------------------

@app.post("/api/analyze-csv")
async def analyze_csv(file: UploadFile = File(...)):

    if not file.filename.lower().endswith(".csv"):

        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file."
        )

    if (
        ddos_model is None
        or botnet_model is None
        or exfil_model is None
    ):

        raise HTTPException(
            status_code=503,
            detail="One or more models are not loaded."
        )

    try:

        contents = await file.read()

        df = pd.read_csv(
            BytesIO(contents)
        )

        required_columns = FEATURES + ["label"]

        missing_columns = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing_columns:

            raise HTTPException(
                status_code=400,
                detail={
                    "message": "CSV is missing required columns.",
                    "missing_columns": missing_columns
                }
            )

        if df.empty:

            raise HTTPException(
                status_code=400,
                detail="The uploaded CSV is empty."
            )

        # Extract features.
        feature_data = df[FEATURES].copy()

        actual_labels = df["label"]

        feature_data = feature_data.apply(
            pd.to_numeric,
            errors="coerce"
        )

        if not np.isfinite(
            feature_data.to_numpy()
        ).all():

            raise HTTPException(
                status_code=400,
                detail=(
                    "CSV contains missing or invalid feature values."
                )
            )

        # ------------------------------------------
        # MODEL 1: ISOLATION FOREST
        # ------------------------------------------

        isolation_predictions = ddos_model.predict(
            feature_data
        )

        anomaly_scores = ddos_model.decision_function(
            feature_data
        )

        # ------------------------------------------
        # MODEL 2: XGBOOST
        # ------------------------------------------

        predicted_classes = botnet_model.predict(
            feature_data
        )

        probabilities = botnet_model.predict_proba(
            feature_data
        )

        # Record-wise confidence.
        record_confidence = np.max(
            probabilities,
            axis=1
        )

        average_detection_confidence = float(
            np.mean(record_confidence) * 100
        )

        # ------------------------------------------
        # MODEL 3: AUTOENCODER
        # ------------------------------------------

        input_array = feature_data.to_numpy(
            dtype=np.float32
        )

        scaled_input = (
            (input_array - scaling_min)
            / (scaling_max - scaling_min + 1e-8)
        )

        tensor_input = torch.tensor(
            scaled_input,
            dtype=torch.float32
        )

        with torch.no_grad():

            reconstructed = exfil_model(
                tensor_input
            )

            reconstruction_errors = torch.mean(
                (reconstructed - tensor_input) ** 2,
                dim=1
            ).numpy()

        # ------------------------------------------
        # TRAFFIC SEVERITY CALCULATION
        # ------------------------------------------

        severity_scores, severity_categories = (
            calculate_traffic_severity(feature_data)
        )

        severity_distribution = {
            category: int(
                np.sum(severity_categories == category)
            )
            for category in SEVERITY_LEVELS
        }

        high_severity_count = (
            severity_distribution["High"]
            + severity_distribution["Critical"]
        )

        # ------------------------------------------
        # ACTUAL LABEL DISTRIBUTION
        # ------------------------------------------

        actual_distribution = {
            str(label): int(count)

            for label, count in
            actual_labels.value_counts(
                dropna=False
            ).items()
        }

        # ------------------------------------------
        # PREDICTED CLASS DISTRIBUTION
        # ------------------------------------------

        predicted_distribution = {
            CLASS_NAMES.get(int(label), str(label)): int(count)

            for label, count in
            pd.Series(predicted_classes).value_counts().items()
        }

        # ------------------------------------------
        # THREATS DETECTED
        # ------------------------------------------

        threat_classes = {
            1,
            2,
            3
        }

        threats_detected = int(
            np.sum(
                np.isin(
                    predicted_classes,
                    list(threat_classes)
                )
            )
        )

        # ------------------------------------------
        # RECORD PREVIEW
        # ------------------------------------------

        preview = []

        for i in range(min(10, len(df))):

            preview.append({

                "actual_label": str(
                    actual_labels.iloc[i]
                ),

                "predicted_class": CLASS_NAMES.get(
                    int(predicted_classes[i]),
                    str(predicted_classes[i])
                ),

                "is_anomaly": bool(
                    isolation_predictions[i] == -1
                ),

                "anomaly_score": float(
                    anomaly_scores[i]
                ),

                "exfil_reconstruction_error": float(
                    reconstruction_errors[i]
                ),

                "severity_score": float(
                    severity_scores[i]
                ),

                "severity": str(
                    severity_categories[i]
                ),

                "detection_confidence": float(
                    record_confidence[i] * 100
                )
            })

        # ------------------------------------------
        # FINAL API RESPONSE
        # ------------------------------------------

        return {

            "filename": file.filename,

            # Dashboard metric 1
            "total_records": int(len(df)),

            # Dashboard metric 2
            "threats_detected": threats_detected,

            "actual_label_distribution": actual_distribution,

            "predicted_class_distribution": predicted_distribution,

            "isolation_forest_anomaly_count": int(
                np.sum(isolation_predictions == -1)
            ),

            # Dashboard metric 3
            "severity_distribution": severity_distribution,

            "high_severity_count": high_severity_count,

            # Dashboard metric 4
            "average_detection_confidence": round(
                average_detection_confidence,
                2
            ),

            "autoencoder_average_reconstruction_error": float(
                np.mean(reconstruction_errors)
            ),

            "autoencoder_threshold_configured": False,

            "severity_calculation": (
                "Baseline-relative statistical traffic risk"
            ),

            "preview": preview,

            "note": (
                "Predictions use models trained on synthetic data. "
                "Threats detected are XGBoost predicted attack classes. "
                "Severity is a provisional baseline-relative traffic-risk "
                "score, not confirmed incident impact. "
                "Detection confidence is average maximum class probability, "
                "not model accuracy. "
                "Autoencoder reconstruction errors are scores only; "
                "no anomaly threshold has been calibrated. "
                "Validate on representative ICS/SCADA traffic."
            )
        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"CSV analysis failed: {exc}"
        ) from exc



