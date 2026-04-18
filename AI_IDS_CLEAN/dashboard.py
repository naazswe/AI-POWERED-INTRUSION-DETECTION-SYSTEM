import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# Page Config (MUST BE FIRST)
# -----------------------------
st.set_page_config(
    page_title="AI-Powered Intrusion Detection System",
    layout="wide"
)

# -----------------------------
# Authentication
# -----------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

def login():
    st.title("🔐 IDS Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.logged_in = True
            st.success("Login Successful")
        else:
            st.error("Invalid Credentials")

if not st.session_state.logged_in:
    login()
    st.stop()

# -----------------------------
# Title
# -----------------------------
st.title("🔐 AI-Powered Intrusion Detection Dashboard")
st.markdown("Real-time Network Traffic Classification using Machine Learning")

# -----------------------------
# Sidebar Navigation
# -----------------------------
page = st.sidebar.radio("Select Mode", ["Single Prediction", "Batch Prediction"])

API_URL = "http://127.0.0.1:8000/predict"

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Flow Bytes/s",
    "Flow Packets/s"
]

# =============================
# SINGLE PREDICTION
# =============================
if page == "Single Prediction":

    st.subheader("📊 Single Traffic Prediction")

    cols = st.columns(2)
    input_data = {}

    for i, feature in enumerate(FEATURES):
        with cols[i % 2]:
            input_data[feature] = st.number_input(
                feature,
                min_value=0.0,
                value=0.0,
                step=1.0
            )

    if st.button("🔍 Predict"):

        payload = {"features": list(input_data.values())}

        try:
            response = requests.post(API_URL, json=payload)

            if response.status_code != 200:
                st.error("API Error. Check backend.")
                st.stop()

            data = response.json()

            prediction = data["prediction"]
            label = data["result"]
            probability = data["malicious_probability"]

            # Display Result
            if prediction == 0:
                st.success("✅ BENIGN Traffic")
            else:
                st.error("🚨 MALICIOUS Traffic Detected!")

            st.info(f"Malicious Probability: {round(probability * 100, 2)}%")

            # Probability Graph
            st.subheader("📈 Attack Probability")

            fig, ax = plt.subplots()
            ax.bar(["Benign", "Malicious"], [1 - probability, probability])
            ax.set_ylim(0, 1)
            ax.set_ylabel("Probability")
            ax.set_title("Traffic Classification Confidence")

            st.pyplot(fig)

        except Exception as e:
            st.error(f"Connection Error: {e}")

# =============================
# BATCH PREDICTION
# =============================
elif page == "Batch Prediction":

    st.subheader("📁 Batch Prediction")

    uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])

    if uploaded_file:

        df = pd.read_csv(uploaded_file)
        st.write("Preview:", df.head())

        if st.button("🚀 Run Prediction"):

            predictions = []
            probabilities = []

            for _, row in df.iterrows():

                payload = {"features": row.values.tolist()}
                response = requests.post(API_URL, json=payload)

                if response.status_code == 200:
                    data = response.json()
                    predictions.append(data["prediction"])
                    probabilities.append(data["malicious_probability"])
                else:
                    predictions.append(None)
                    probabilities.append(None)

            df["Prediction"] = predictions
            df["Malicious Probability"] = probabilities
            df["Label"] = df["Prediction"].map({0: "BENIGN", 1: "MALICIOUS"})

            st.success("Batch Prediction Complete")
            st.write(df.head())

            # Pie Chart
            st.subheader("📊 Traffic Distribution")

            counts = df["Label"].value_counts()

            fig2, ax2 = plt.subplots()
            ax2.pie(counts, labels=counts.index, autopct="%1.1f%%")
            ax2.set_title("Benign vs Malicious Traffic")

            st.pyplot(fig2)

            st.download_button(
                "⬇ Download Results",
                df.to_csv(index=False),
                file_name="ids_results.csv",
                mime="text/csv"
            )

# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.markdown("AI-Powered IDS | Final Year Cybersecurity Project")