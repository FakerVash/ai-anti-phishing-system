from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from virustotal_service import check_url_virustotal
from detector import heuristic_analysis, check_identity_and_typosquatting
from ai_analyzer import analyze_with_ai
from logger import log_analysis
from dotenv import load_dotenv
import re
import os

# Cargar variables de entorno desde .env
load_dotenv()

app = Flask(__name__)
CORS(app)  # Habilitar CORS para requests desde otros dominios

# Configuración de servicios para Health Check
vt_configured = os.getenv("VT_API_KEY") is not None and os.getenv("VT_API_KEY") != "your_vt_api_key_here"
gemini_configured = os.getenv("CLAUDE_API_KEY") is not None and os.getenv("CLAUDE_API_KEY") != "your_claude_api_key_here"

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
        r'([a-zA-Z0-9._-]+)'       # dominio (agregado _ para subdominios como kucoinlogin_)
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
    
    # Normalizar URL 
    url = normalize_url(url)
    print(f" URL normalizada: {url}")

    # 1. Análisis de Identidad (Motor VIP y Anti-Suplantación)
    print("🔍 Iniciando Motor de Identidad...")
    identity_result = check_identity_and_typosquatting(url)
    
    # 2. Análisis heurístico
    print(" Iniciando análisis heurístico...")
    try:
        heuristic_result = heuristic_analysis(url)
        print(f" Análisis heurístico completado: Score={heuristic_result['score']}, Nivel={heuristic_result['risk_level']}")
    except Exception as e:
        print(f" Error en análisis heurístico: {e}")
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

    # 3. Análisis con IA (Claude)
    print("🤖 Iniciando análisis con IA...")
    try:
        ai_result = analyze_with_ai(url, vt_result, heuristic_result, identity_result)
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

    # 4. Construir respuesta unificada (Lógica de votación 2 de 3)
    
    # Obtener nivel de riesgo de IA para la votación
    ai_risk_level = ai_result.get("ai_risk_level", "Desconocido")

    votes = {
        "virustotal": 0,
        "heuristic": 0,
        "ai": 0
    }
    
    # Voto 1: VirusTotal
    # Consideramos phishing si es malicioso o sospechoso (al menos 1 motor)
    vt_malicious = vt_result.get("stats", {}).get("malicious", 0)
    vt_suspicious = vt_result.get("stats", {}).get("suspicious", 0)
    total_vt_alerts = vt_malicious + vt_suspicious
    
    if vt_result.get("status") in ["phishing", "malicious"] or total_vt_alerts > 0:
        votes["virustotal"] = 1
        
    # Voto 2: Heurístico
    # Consideramos phishing si el score es alto (>= 60)
    # Consideramos sospechoso si el score es medio (>= 20, cuenta como medio voto para el mensaje)
    if heuristic_result["score"] >= 60:
        votes["heuristic"] = 1
    elif heuristic_result["score"] >= 20:
        votes["heuristic"] = 0.5
        
    # Voto 3: IA
    # Consideramos phishing si el riesgo es Alto o Crítico
    # Consideramos sospechoso si es Medio (cuenta como medio voto para el mensaje)
    ai_risk_lower = ai_risk_level.lower()
    if "alto" in ai_risk_lower or "high" in ai_risk_lower or "crítico" in ai_risk_lower or "critical" in ai_risk_lower:
        votes["ai"] = 1
    elif "medio" in ai_risk_lower or "medium" in ai_risk_lower or "precaución" in ai_risk_lower:
        votes["ai"] = 0.5

    total_votes = sum(votes.values())
    
    # Conteo de alertas para el mensaje (cuantos sistemas avisaron algo)
    systems_alerting = sum(1 for v in votes.values() if v > 0)
    
    # Lógica de decisión final combinando Identidad + Votación
    if identity_result["status"] == "verified":
        global_status = "safe"
        global_reason = identity_result["reason"]
    elif identity_result["status"] == "impersonation":
        global_status = "phishing"
        global_reason = identity_result["reason"]
    elif total_votes >= 2:
        global_status = "phishing"
        global_reason = f"ALERTA: {systems_alerting}/3 sistemas detectaron amenazas críticas. (Regla de consenso)"
    elif total_votes >= 0.5:
        global_status = "suspicious"
        if systems_alerting >= 2:
            global_reason = f"URL SOSPECHOSA: {systems_alerting}/3 sistemas detectaron señales de alerta combinadas."
        else:
            global_reason = f"PRECAUCIÓN: {systems_alerting}/3 sistemas detectaron posibles riesgos."
    else:
        global_status = "safe"
        global_reason = "No se detectaron amenazas significativas (0/3 sistemas)"

    response = {
        "status": global_status,
        "reason": global_reason,
        "url": url,
        "identity": identity_result, # Incluimos el resultado de identidad
        
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

    # Log the result
    log_analysis(response)

    return jsonify(response), 200


@app.route("/chat", methods=["POST"])
def chat():
    """
    Endpoint para chat interactivo con IA sobre URLs analizadas.
    """
    # Importar dentro de la función para evitar dependencias circulares si las hubiera
    from chat_service import chat_with_ai, get_suggested_questions
    
    data = request.get_json()
    
    if not data:
        return jsonify({
            "status": "error",
            "answer": "No se recibieron datos."
        }), 400
    
    url = data.get("url", "").strip()
    question = data.get("question", "").strip()
    analysis_context = data.get("analysis_context", {})
    
    # Validaciones
    if not question:
        return jsonify({
            "status": "error",
            "answer": "Pregunta no proporcionada."
        }), 400
    
    # Permitir chat sin URL/Contexto (Chat General)
    if not url:
        url = "General"
    
    # Generar respuesta
    result = chat_with_ai(url, question, analysis_context)
    
    # Agregar sugerencias si es la primera pregunta
    if result.get("status") == "success":
        result["suggested_questions"] = get_suggested_questions(analysis_context)
    
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True)