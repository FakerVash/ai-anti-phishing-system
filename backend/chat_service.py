"""
Servicio de chat interactivo con IA.
Permite a los usuarios hacer preguntas sobre URLs analizadas.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Importar Claude
CLAUDE_AVAILABLE = False
try:
    from anthropic import Anthropic
    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False

# Configuración
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-3-haiku-20240307")

if CLAUDE_AVAILABLE and CLAUDE_API_KEY and CLAUDE_API_KEY != "your_claude_api_key_here":
    client = Anthropic(api_key=CLAUDE_API_KEY)
else:
    CLAUDE_AVAILABLE = False


def create_chat_prompt(url, question, analysis_context):
    """
    Crea un prompt contextual para el chat.
    """
    ai_analysis = analysis_context.get("ai_analysis", "No disponible")
    ai_risk = analysis_context.get("ai_risk_level", "Desconocido")
    heuristic = analysis_context.get("heuristic", {})
    vt = analysis_context.get("virustotal", {})
    
    # CONOCIMIENTO DEL PROYECTO (Contexto estático)
    PROJECT_KNOWLEDGE = """
    **SOBRE ESTE PROYECTO (Sistema Anti-Phishing con IA):**
    - **Nombre:** CyberGuard AI Security System.
    - **Propósito:** Blindar a los usuarios contra el phishing y robo de identidad.
    - **Componentes de Análisis:** 
        1. **Motor de Identidad (Identity Motor):** Nuestra joya de la corona. Reconoce dominios oficiales de bancos y marcas famosas para dar fe de su legitimidad o detectar suplantaciones (typosquatting).
        2. **Heurística Avanzada:** Escanea el ADN de la URL buscando trucos técnicos (IPs, caracteres raros, palabras de urgencia).
        3. **VirusTotal:** Consulta el historial mundial de reportes de virus y estafas.
        4. **Cerebro IA (Claude):** Orquesta todo para dar un veredicto humano.
    """
    
    # Prompt simplificado para chat general (sin URL analizada o URL "General")
    if not analysis_context or url == "General":
        prompt = f"""Eres 'CyberGuard', el asistente oficial de este Sistema Anti-Phishing.
        
**TU IDENTIDAD:**
- Eres el experto residente de este sistema.
- Conoces perfectamente cómo funciona el proyecto (backend, heurística, IA).
- Tu objetivo es educar y guiar al usuario.

**CONOCIMIENTO DEL PROYECTO:**
{PROJECT_KNOWLEDGE}

**PREGUNTA DEL USUARIO:**
"{question}"

**TUS INSTRUCCIONES:**
1. **Responde dudas sobre el proyecto:** Si preguntan "qué hace esto", "cómo funciona", "para qué sirve la web", USA la información de **CONOCIMIENTO DEL PROYECTO**.
2. **Ciberseguridad General:** Responde dudas generales (contraseñas, seguridad, etc.) con tu conocimiento experto.
3. **Personalidad:** Sé profesional, entusiasta sobre el proyecto y muy claro.
"""
        return prompt

    # Prompt para chat con contexto de análisis (Cuando hay una URL)
    identity = analysis_context.get("identity", {})
    identity_status = identity.get("status", "unknown")
    
    prompt = f"""Eres 'CyberGuard', el asistente experto de élite de este Sistema Anti-Phishing.
    
**CONOCIMIENTO DEL PROYECTO:**
{PROJECT_KNOWLEDGE}

**CONTEXTO DEL ANÁLISIS ACTUAL:**
El usuario ha analizado la URL: {url}
- **Veredicto de Identidad:** {identity_status.upper()} {"(Confirmado como " + identity.get('name', '') + ")" if identity_status == 'verified' else ""}
- **Riesgo General:** {ai_risk}
- **Detalle Técnico IA:** {ai_analysis}
- **Score Heurístico:** {heuristic.get('score', 0)}/100
- **Detecciones VirusTotal:** {vt.get('stats', {}).get('malicious', 0)} amenazas confirmadas.

**PREGUNTA DEL USUARIO:**
"{question}"

**REGLAS DE ORO PARA TUS RESPUESTAS:**
1. **Tolerancia Cero a la Suplantación:** Si el sistema detecta "IMPERSONATION", tu prioridad absoluta es advertir al usuario de que alguien intenta engañarle. Nunca digas "no es malicioso" si se detecta Typosquatting (suplantación de nombre). Explica que el fraude empieza con el engaño visual.
2. **Experticismo Proactivo:** No te limites a responder. Si ves un riesgo alto, advierte con firmeza. Si es seguro y está verificado por nuestro Motor de Identidad, dale tranquilidad total al usuario explicando POR QUÉ confiamos en ese dominio.
3. **Formato Rico:** USA **negritas** para conceptos clave, `código` para partes de la URL y listas punteadas para pasos a seguir.
4. **Coherencia:** Mantén consistencia con el veredicto dado anteriormente. No contradigas el reporte técnico.
5. **Educación:** Explica conceptos como "Typosquatting", "Títulos de confianza" o "Entropía" si son relevantes para la pregunta.

**TU VOZ:**
Eres profesional, servicial y experto en seguridad de élite. No eres un bot aburrido, eres un defensor del usuario. No dudes en ser tajante si detectas una estafa.
"""
    return prompt


def chat_with_ai(url, question, analysis_context):
    """
    Genera respuesta de chat usando Claude.
    
    Args:
        url: URL analizada
        question: Pregunta del usuario
        analysis_context: Contexto del análisis previo
    
    Returns:
        dict con la respuesta
    """
    
    # Validar pregunta
    if not question or len(question.strip()) < 3:
        return {
            "status": "error",
            "answer": "Por favor escribe una pregunta válida."
        }
    
    if len(question) > 500:
        return {
            "status": "error",
            "answer": "La pregunta es demasiado larga. Por favor sé más conciso."
        }
    
    # Si Claude no está disponible
    if not CLAUDE_AVAILABLE:
        return {
            "status": "error",
            "answer": "El chat con IA no está disponible en este momento. Por favor intenta más tarde."
        }
    
    try:
        # Debug logs
        print(f"💬 Procesando pregunta: {question}")
        print(f"🔑 Using API Key: {CLAUDE_API_KEY[:5]}...{CLAUDE_API_KEY[-4:] if CLAUDE_API_KEY else 'None'}")
        
        # Crear prompt
        prompt = create_chat_prompt(url, question, analysis_context)
        
        # Llamar a Claude
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=800,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        # Extraer respuesta
        answer = message.content[0].text.strip()
        print(f"✅ Respuesta recibida de IA: {len(answer)} chars")
        
        return {
            "status": "success",
            "answer": answer,
            "source": "claude"
        }
    
    except Exception as e:
        import traceback
        print(f"❌ Error CRÍTICO en chat con IA: {str(e)}")
        traceback.print_exc()
        return {
            "status": "error",
            "answer": f"Error técnico: {str(e)}"
        }


def get_suggested_questions(analysis_context):
    """
    Genera preguntas sugeridas inteligentes basadas en el tipo de hallazgo.
    """
    ai_risk = analysis_context.get("ai_risk_level", "").lower()
    identity = analysis_context.get("identity", {})
    identity_status = identity.get("status", "unknown")
    
    suggestions = []
    
    if identity_status == "verified":
        suggestions.append(f"¿Por qué confían en {identity.get('name')}?")
        suggestions.append("¿Cómo sé que no es un clon perfecto?")
        suggestions.append("¿Qué es un dominio de confianza?")
    elif identity_status == "impersonation":
        suggestions.append("¿Cómo detectaron la suplantación?")
        suggestions.append("¿A quién intentan imitar?")
        suggestions.append("¿Qué hago si puse mi clave ahí?")
    elif "crítico" in ai_risk or "alto" in ai_risk:
        suggestions.append("¿Qué hace que esta URL sea tan peligrosa?")
        suggestions.append("¿Cómo robarían mi información?")
        suggestions.append("¿Cómo puedo reportar este sitio?")
    else:
        suggestions.append("¿Qué revisaron para decir que es seguro?")
        suggestions.append("¿Qué es el phishing?")
        suggestions.append("Consejos para no caer en estafas")
    
    return suggestions[:3]
