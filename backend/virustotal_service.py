import os
import requests
import time

API_KEY = os.getenv("VT_API_KEY")
VT_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses"

headers = {
    "x-apikey": API_KEY
}

def check_url_virustotal(url):
    
    if not API_KEY:
        print("❌ ERROR: VT_API_KEY no está configurada")
        return {
            "status": "error",
            "reason": "API Key de VirusTotal no configurada. Verifica la variable de entorno VT_API_KEY."
        }
    
    print(f"✅ API Key configurada: {API_KEY[:10]}...")
    print(f"🔍 Analizando URL: {url}")
    
    # 1️⃣ Enviar URL a análisis
    try:
        submit_response = requests.post(
            VT_SUBMIT_URL,
            headers=headers,
            data={"url": url},
            timeout=15
        )
        
        print(f"📤 Respuesta de envío: {submit_response.status_code}")
        
        if submit_response.status_code == 401:
            return {
                "status": "error",
                "reason": "API Key inválida. Verifica tu clave de VirusTotal."
            }
        
        if submit_response.status_code != 200:
            error_msg = submit_response.json().get("error", {}).get("message", "Error desconocido")
            return {
                "status": "error",
                "reason": f"VirusTotal respondió con error {submit_response.status_code}: {error_msg}"
            }
        
        response_data = submit_response.json()
        print(f"📊 Datos recibidos: {response_data}")
        
        analysis_id = response_data["data"]["id"]
        print(f"🆔 ID de análisis: {analysis_id}")
        
    except requests.exceptions.Timeout:
        return {
            "status": "error",
            "reason": "Tiempo de espera agotado al conectar con VirusTotal."
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "error",
            "reason": "No se pudo conectar con VirusTotal. Verifica tu conexión a internet."
        }
    except KeyError as e:
        return {
            "status": "error",
            "reason": f"Respuesta inesperada de VirusTotal: falta el campo {str(e)}"
        }
    except Exception as e:
        print(f"❌ Error al enviar URL: {str(e)}")
        return {
            "status": "error",
            "reason": f"Error al enviar la URL: {str(e)}"
        }

    # 2️⃣ Esperar más tiempo para que el análisis se complete
    print("⏳ Esperando resultados del análisis...")
    time.sleep(15)  # 15 segundos para esperar análisis completo

    # 3️⃣ Obtener resultados - REINTENTAR SI NO ESTÁ COMPLETO
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            analysis_response = requests.get(
                f"{VT_ANALYSIS_URL}/{analysis_id}",
                headers=headers,
                timeout=15
            )
            
            print(f"📥 Respuesta de análisis (intento {retry_count + 1}): {analysis_response.status_code}")
            
            if analysis_response.status_code != 200:
                if retry_count < max_retries - 1:
                    print(f"⏳ Análisis no listo, reintentando en 5 segundos...")
                    time.sleep(5)
                    retry_count += 1
                    continue
                else:
                    return {
                        "status": "error",
                        "reason": f"Error al obtener resultados después de {max_retries} intentos. El análisis puede no estar listo."
                    }
            
            data = analysis_response.json()
            
            # Verificar si el análisis está completo
            analysis_status = data["data"]["attributes"].get("status", "")
            print(f"📊 Estado del análisis: {analysis_status}")
            
            if analysis_status == "queued" and retry_count < max_retries - 1:
                print(f"⏳ Análisis en cola, reintentando en 5 segundos...")
                time.sleep(5)
                retry_count += 1
                continue
            
            print(f"📊 Análisis completo: {data}")
            
            # Verificar que los datos existan
            if "data" not in data or "attributes" not in data["data"]:
                return {
                    "status": "error",
                    "reason": "Estructura de respuesta inválida de VirusTotal."
                }
            
            stats = data["data"]["attributes"].get("stats", {})
            print(f"📈 Estadísticas: {stats}")
            break  # Salir del bucle si todo está bien
            
        except requests.exceptions.Timeout:
            if retry_count < max_retries - 1:
                print(f"⏳ Timeout, reintentando...")
                retry_count += 1
                time.sleep(5)
                continue
            return {
                "status": "error",
                "reason": "Tiempo de espera agotado al obtener resultados."
            }
        except requests.exceptions.ConnectionError:
            return {
                "status": "error",
                "reason": "Perdida de conexión con VirusTotal."
            }
        except Exception as e:
            print(f"❌ Error al obtener resultados: {str(e)}")
            if retry_count < max_retries - 1:
                retry_count += 1
                time.sleep(5)
                continue
            return {
                "status": "error",
                "reason": f"Error al obtener resultados: {str(e)}"
            }

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    
    # Total de detecciones negativas
    total_threats = malicious + suspicious
    print(f"{VT_ANALYSIS_URL}/{analysis_id}")
    print(f"🎯 Maliciosos: {malicious}, Sospechosos: {suspicious}, Inofensivos: {harmless}, No detectados: {undetected}")
    print(f"⚠️ Total amenazas detectadas: {total_threats}")

    # Extraer información adicional de los motores que detectaron
    results = data["data"]["attributes"].get("results", {})
    detection_engines = []
    categories = []
    
    for engine_name, engine_result in results.items():
        category = engine_result.get("category", "")
        result = engine_result.get("result", "")
        
        if category in ["malicious", "suspicious"]:
            detection_engines.append(engine_name)
            if result and result not in categories:
                categories.append(result)

    reasons = []

    # Si hay 5 o más detecciones, es phishing
    if total_threats >= 5:
        reasons.append(
            f"{total_threats} motores de seguridad identificaron esta URL como amenaza "
            f"({malicious} maliciosos, {suspicious} sospechosos)."
        )
        reasons.append(
            "Este nivel de consenso indica una campaña activa de phishing o malware."
        )
        return {
            "status": "phishing",
            "risk_score": min(100, total_threats * 5),
            "reason": " ".join(reasons),
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            },
            "detection_engines": detection_engines[:10],  # Primeros 10
            "categories": categories[:5],  # Primeras 5 categorías
            "analysis_url": f"{VT_ANALYSIS_URL}/{analysis_id}"
        }

    # Si hay entre 2-4 detecciones, es sospechoso
    if total_threats >= 2:
        reasons.append(
            f"Se detectaron {total_threats} reportes de amenaza "
            f"({malicious} maliciosos, {suspicious} sospechosos)."
        )
        reasons.append(
            "Aunque no hay consenso masivo, este patrón sugiere riesgo moderado a alto."
        )
        return {
            "status": "suspicious",
            "risk_score": 30 + (total_threats * 10),
            "reason": " ".join(reasons),
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            },
            "detection_engines": detection_engines,
            "categories": categories,
            "analysis_url": f"{VT_ANALYSIS_URL}/{analysis_id}"
        }
    
    # Si hay 1 detección, advertencia menor
    if total_threats == 1:
        return {
            "status": "suspicious",
            "risk_score": 25,
            "reason": "Un motor de seguridad reportó esta URL como potencialmente peligrosa. Se recomienda precaución.",
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            },
            "detection_engines": detection_engines,
            "categories": categories,
            "analysis_url": f"{VT_ANALYSIS_URL}/{analysis_id}"
        }

    return {
        "status": "safe",
        "risk_score": 5,
        "reason": (
            "La mayoría de motores de seguridad no reportan actividad maliciosa. "
            "Aun así, siempre es recomendable verificar el contexto del sitio."
        ),
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        },
        "detection_engines": [],
        "categories": [],
        "analysis_url": f"{VT_ANALYSIS_URL}/{analysis_id}"
    }
