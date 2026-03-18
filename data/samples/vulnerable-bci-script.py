"""
SAMPLE VULNERABLE BCI SCRIPT — FOR TESTING ONLY

This file contains INTENTIONAL security anti-patterns that the BCI Security
scanner should detect. It is a test fixture, not real code. None of the
API keys, subject names, or endpoints are real.

Expected findings when scanned with /bci-scan:
  - Rule 1: Unencrypted LSL stream, unauthenticated BLE, raw serial
  - Rule 2: PII in EDF filename, subject name in header, no consent sidecar
  - Rule 3: Hardcoded API key, HTTP endpoint
  - Rule 4: Neural biometric storage, cognitive state classification,
            clinical diagnosis, missing consent, cross-border transfer

Run: /bci-scan data/samples/vulnerable-bci-script.py
"""

# ===== Rule 1: Transport Security =====

# LSL stream with no encryption
from pylsl import StreamOutlet, StreamInfo
info = StreamInfo("ADHD_EEG", "EEG", 5, 256, "float32", "adhd-study-001")
outlet = StreamOutlet(info)

# BLE connection without bonding
from bleak import BleakClient
async def connect_headband():
    client = BleakClient("AA:BB:CC:DD:EE:FF")
    await client.connect()
    # No bonding, no pairing, no encrypted characteristics
    data = await client.read_gatt_char("00002a19-0000-1000-8000-00805f9b34fb")

# Serial connection with no device authentication
import serial
ser = serial.Serial(port="/dev/ttyUSB0", baudrate=115200)

# BrainFlow without encryption
from brainflow.board_shim import BoardShim, BrainFlowInputParams
params = BrainFlowInputParams()
params.ip_protocol = 0  # Unencrypted
board = BoardShim(0, params)


# ===== Rule 2: Data Storage PII =====

# PII in filename
import pyedflib
writer = pyedflib.EdfWriter("John_Smith_ADHD_session3.edf", 5)
writer.setPatientName("Jane Doe")  # Subject name in EDF header
writer.setPatientAdditional("DOB: 1998/03/22, Diagnosis: ADHD F90.2")

# Neural data to CSV without anonymization
import pandas as pd
eeg_df = pd.DataFrame({"eeg_channel_F3": [1.2, 3.4], "eeg_channel_F4": [5.6, 7.8]})
eeg_df.to_csv("participant_Jane_Doe_resting.csv")

# No .consent.json sidecar for any of these files


# ===== Rule 3: API Credentials =====

# Hardcoded Emotiv API key
EMOTIV_API_KEY = "<REPLACE-WITH-YOUR-EMOTIV-API-KEY>"
CORTEX_CLIENT_SECRET = "<REPLACE-WITH-YOUR-CORTEX-SECRET>"

# HTTP endpoint for neural data upload (not HTTPS)
import requests
response = requests.post(
    "http://eeg-cloud.example.com/api/v1/upload",
    headers={"Authorization": f"Bearer {EMOTIV_API_KEY}"},
    files={"eeg_data": open("John_Smith_ADHD_session3.edf", "rb")}
)


# ===== Rule 4: PII in Neural Data Pipelines =====

# Neural biometric storage (PII-010)
brain_fingerprint = compute_neural_signature(eeg_data)
eeg_biometric_template = extract_brain_print(subject_data)

# Cognitive state classification without consent gate (PII-011)
emotion_detection_result = classifier.predict(eeg_features)
attention_score = model.score_attention(raw_eeg)
mental_state = decode_cognitive_state(filtered_signal)
stress_level = estimate_stress(alpha_beta_ratio)

# Clinical diagnosis in BCI metadata (PII-013)
subject_config = {
    "diagnosis": "ADHD",
    "icd_10": "F90.2",
    "dsm_5_code": "314.01",
    "condition": "ADHD, Combined Presentation"
}

# Raw neural data export without anonymization (PII-012)
export_raw_eeg(original_unfiltered_neural_data, "raw_export.edf")

# Cross-border neural data transfer (PII-017)
upload_to_cloud(neural_eeg_data, endpoint="s3://us-east-1/eeg-bucket/")

# Neurostimulation without safety bounds (PII-018)
stimulation_config = {
    "current_mA": 2.5,
    "voltage_limit": None,  # No limit set
    "amplitude_level": "high"
}
tdcs_stimulate(config=stimulation_config)
# No max current check, no session duration limit, no emergency shutoff
