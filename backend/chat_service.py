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
    
    prompt = f"""Eres un asistente experto en ciberseguridad especializado en phishing y protección online.

**CONTEXTO:**
El usuario analizó esta URL: {url}

**ANÁLISIS PREVIO REALIZADO:**

Análisis con IA:
- Nivel de riesgo: {ai_risk}
- Análisis: {ai_analysis}

Análisis Heurístico:
- Score: {heuristic.get('score', 0)}/100
- Nivel: {heuristic.get('risk_level', 'DESCONOCIDO')}
- Indicadores: {len(heuristic.get('indicators', []))}

VirusTotal:
- Maliciosos: {vt.get('stats', {}).get('malicious', 0)}
- Sospechosos: {vt.get('stats', {}).get('suspicious', 0)}

**PREGUNTA DEL USUARIO:**
"{question}"

**TUS INSTRUCCIONES:**

1. **SOLO** responde preguntas relacionadas con:
   - La URL analizada
   - Ciberseguridad y phishing
   - Protección online
   - Conceptos técnicos mencionados en el análisis

2. Si la pregunta NO está relacionada, responde:
   "Solo puedo ayudarte con preguntas sobre ciberseguridad y la URL que analizaste. ¿Tienes alguna duda sobre esta URL o sobre cómo protegerte del phishing?"

3. Usa el contexto del análisis previo para dar respuestas específicas

4. Sé educativo pero conciso (2-3 párrafos máximo)

5. Usa emojis moderadamente para mejor UX (🚨 ⚠️ ✅ 💡 🛡️)

6. Si preguntan qué hacer después de ser víctima, da pasos concretos

**FORMATO DE RESPUESTA:**
Respuesta directa en texto plano, sin formato especial.
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
    Genera preguntas sugeridas basadas en el análisis.
    """
    ai_risk = analysis_context.get("ai_risk_level", "").lower()
    heuristic_score = analysis_context.get("heuristic", {}).get("score", 0)
    
    suggestions = []
    
    # Siempre incluir
    suggestions.append("¿Por qué esta URL es peligrosa/segura?")
    
    # Basado en riesgo
    if "crítico" in ai_risk or "alto" in ai_risk or heuristic_score >= 40:
        suggestions.append("¿Qué pasaría si ingreso mis datos aquí?")
        suggestions.append("¿Qué hago si ya visité este sitio?")
    else:
        suggestions.append("¿Cómo verifico que un sitio es legítimo?")
    
    # Educativas
    suggestions.append("¿Qué es el phishing y cómo me protejo?")
    
    return suggestions[:4]  # Máximo 4 sugerencias
