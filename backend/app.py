from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from virustotal_service import check_url_virustotal
from detector import heuristic_analysis
from ai_analyzer import analyze_with_ai
from dotenv import load_dotenv
import re

# Cargar variables de entorno desde .env
load_dotenv()

app = Flask(__name__)
CORS(app)  # Habilitar CORS para requests desde otros dominios

# Validación y normalización de URL
def normalize_url(url):
    """Agrega https:// si falta el protocolo"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def is_valid_url(url):
    """Valida formato básico de URL"""
    regex = re.compile(
        r'^(https?://)?'         # http o https (opcional ahora)
        r'([a-zA-Z0-9.-]+)'        # dominio
        r'(\.[a-zA-Z]{2,})'        # TLD
        r'(/.*)?$'                # ruta opcional
    )
    return re.match(regex, url)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    """Endpoint de health check"""
    import os
    
    gemini_configured = os.getenv("GEMINI_API_KEY") and os.getenv("GEMINI_API_KEY") != "your_gemini_api_key_here"
    vt_configured = os.getenv("VT_API_KEY") is not None
    
    return jsonify({
        "status": "healthy",
        "services": {
            "virustotal": "configured" if vt_configured else "not_configured",
            "gemini": "configured" if gemini_configured else "not_configured",
            "heuristic": "active"
        }
    }), 200


@app.route("/check", methods=["GET", "POST"])
def check_url():
    # Soportar tanto GET como POST
    if request.method == "POST":
        data = request.get_json()
        url = data.get("url", "").strip() if data else ""
    else:
        url = request.args.get("url", "").strip()

    # Validaciones
    if not url:
        return jsonify({
            "status": "error",
            "reason": "No se ingresó ninguna URL.",
            "risk_score": 0
        }), 400

    # Validar formato antes de normalizar
    if not is_valid_url(url):
        return jsonify({
            "status": "error",
            "reason": "El formato de la URL es inválido. Ejemplo válido: ejemplo.com o https://ejemplo.com",
            "risk_score": 0
        }), 400
    
    # Normalizar URL (agregar https:// si falta)
    url = normalize_url(url)
    print(f"🔗 URL normalizada: {url}")

    # 1. Análisis heurístico
    print("🔍 Iniciando análisis heurístico...")
    try:
        heuristic_result = heuristic_analysis(url)
        print(f"📊 Análisis heurístico completado: Score={heuristic_result['score']}, Nivel={heuristic_result['risk_level']}")
    except Exception as e:
        print(f"❌ Error en análisis heurístico: {e}")
        heuristic_result = {
            "score": 0,
            "risk_level": "DESCONOCIDO",
            "reasons": [],
            "total_indicators": 0
        }

    # 2. Análisis con VirusTotal
    print("🔍 Iniciando análisis con VirusTotal...")
    try:
        vt_result = check_url_virustotal(url)
    except Exception as e:
        return jsonify({
            "status": "error",
            "reason": f"Error interno al analizar la URL con VirusTotal: {str(e)}",
            "risk_score": 0
        }), 500

    if vt_result.get("status") == "error":
        return jsonify({
            "status": "error",
            "reason": vt_result.get("reason", "No se pudo analizar la URL."),
            "risk_score": 0
        }), 500

    print(f"📊 VirusTotal completado: Status={vt_result.get('status')}")

    # 3. Análisis con IA (Gemini)
    print("🤖 Iniciando análisis con IA...")
    try:
        ai_result = analyze_with_ai(url, vt_result, heuristic_result)
        print(f"✅ Análisis con IA completado (fuente: {ai_result.get('source', 'unknown')})")
    except Exception as e:
        print(f"❌ Error en análisis con IA: {e}")
        # Continuar sin análisis de IA
        ai_result = {
            "status": "error",
            "ai_analysis": "El análisis con IA no está disponible en este momento.",
            "ai_risk_level": "Desconocido",
            "ai_recommendations": ["Procede con precaución."]
        }

    # 4. Construir respuesta unificada
    # Determinar el estado global basado en TODOS los análisis (incluyendo IA)
    vt_status = vt_result.get("status", "unknown")
    ai_risk_level = ai_result.get("ai_risk_level", "Desconocido").lower()
    
    # Prioridad: IA > VirusTotal > Heurístico
    # Si la IA detecta Alto/Crítico, tiene prioridad sobre los demás
    if "crítico" in ai_risk_level or "critico" in ai_risk_level:
        global_status = "phishing"
        global_reason = "IA detectó amenaza crítica con análisis contextual"
    elif "alto" in ai_risk_level:
        global_status = "suspicious"
        global_reason = "IA detected riesgo alto mediante análisis de patrones"
    elif vt_status == "phishing" or heuristic_result["score"] >= 60:
        global_status = "phishing"
        global_reason = "Múltiples motores o análisis heurístico crítico"
    elif "medio" in ai_risk_level or vt_status == "suspicious" or heuristic_result["score"] >= 40:
        global_status = "suspicious"
        global_reason = "Indicadores de riesgo detectados"
    else:
        global_status = vt_status if vt_status != "unknown" else "safe"
        global_reason = "No se detectaron amenazas significativas"

    response = {
        "status": global_status,
        "reason": global_reason,
        "url": url,
        
        # Análisis de IA
        "ai_analysis": ai_result.get("ai_analysis", ""),
        "ai_risk_level": ai_result.get("ai_risk_level", "Desconocido"),
        "ai_recommendations": ai_result.get("ai_recommendations", []),
        
        # Análisis Heurístico
        "heuristic": {
            "score": heuristic_result["score"],
            "risk_level": heuristic_result["risk_level"],
            "indicators": heuristic_result["reasons"],
            "total_indicators": heuristic_result["total_indicators"]
        },
        
        # Resultados de VirusTotal
        "virustotal": {
            "status": vt_result.get("status"),
            "risk_score": vt_result.get("risk_score", 0),
            "stats": vt_result.get("stats", {}),
            "detection_engines": vt_result.get("detection_engines", []),
            "categories": vt_result.get("categories", []),
            "analysis_url": vt_result.get("analysis_url", "")
        },
        
        # Información adicional
        "metadata": {
            "ai_source": ai_result.get("source", "unknown"),
            "timestamp": None  # Podrías agregar timestamp aquí
        }
    }

    return jsonify(response), 200


if __name__ == "__main__":
    app.run(debug=True)