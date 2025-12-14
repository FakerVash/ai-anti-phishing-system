from flask import Flask, request, jsonify, render_template
import pandas as pd
import os

app = Flask(__name__)

# -----------------------------
# Cargar base de datos PhishTank
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "phishingtank_online_valid.csv")

data = pd.read_csv(DATA_PATH)

# Columnas importantes
data = data[["url", "target", "phish_detail_url"]]

# Normalización
data["url"] = data["url"].str.lower().str.strip()
phishing_urls = set(data["url"].dropna())

# -----------------------------
# Rutas
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check")
def check_url():
    url = request.args.get("url")

    if not url:
        return jsonify({
            "status": "error",
            "message": "No se proporcionó una URL"
        }), 400

    url = url.lower().strip()

    if url in phishing_urls:
        row = data[data["url"] == url].iloc[0]

        return jsonify({
            "status": "phishing",
            "url": url,
            "target": row["target"],
            "phish_detail_url": row["phish_detail_url"]
        })

    return jsonify({
        "status": "safe",
        "url": url
    })


@app.route("/stats")
def stats():
    return jsonify({
        "total_urls_phishing": len(phishing_urls)
    })


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
