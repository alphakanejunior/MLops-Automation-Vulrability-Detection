from flask import Flask, request, jsonify, render_template
import joblib

app = Flask(__name__)

# Charger le modèle et le vectorizer
model = joblib.load("model/spam_model.pkl")
vectorizer = joblib.load("model/vectorizer.pkl")


# Route homepage
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


# Endpoint API pour curl / JSON
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Message manquant"}), 400

    message = data["message"]
    vect = vectorizer.transform([message])
    prediction = model.predict(vect)[0]

    return jsonify({"message": message, "prediction": "SPAM" if prediction == 1 else "HAM"})


# Endpoint pour le frontend
@app.route("/predict_front", methods=["POST"])
def predict_front():
    data = request.get_json()
    message = data.get("message", "")
    vect = vectorizer.transform([message])
    prediction = model.predict(vect)[0]
    return jsonify({"prediction": "SPAM ❌" if prediction == 1 else "HAM ✅"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
