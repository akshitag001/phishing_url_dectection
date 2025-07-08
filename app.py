from flask import Flask, request, render_template
import pickle
import pandas as pd
from features import extract_features

# --- Load model ---
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/predict', methods=["POST"])
def predict():
    url = request.form.get("url")
    features = extract_features(url)
    df = pd.DataFrame([features])

    prob = model.predict_proba(df)[0][1]
    prediction = model.predict(df)[0]

    result = {
        "url": url,
        "prediction": "Phishing ⚠️" if prediction == 1 else "Legit ✅",
        "probability": round(prob * 100, 2)
    }

    return render_template("result.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

