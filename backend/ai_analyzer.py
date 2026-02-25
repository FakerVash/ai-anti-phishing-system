"""
Servicio de análisis con IA usando Anthropic Claude.
Analiza resultados de VirusTotal y análisis heurístico para proporcionar
explicaciones contextuales y recomendaciones personalizadas.
"""

import os
import json
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Importar Claude con manejo robusto de errores
CLAUDE_AVAILABLE = False
try:
    from anthropic import Anthropic
    CLAUDE_AVAILABLE = True
    print("✅ Librería anthropic importada correctamente")
except ImportError as e:
    CLAUDE_AVAILABLE = False
    print(f"⚠️ anthropic no está instalado: {e}")
except Exception as e:
    CLAUDE_AVAILABLE = False
    print(f"⚠️ Error al importar anthropic: {e}")

# Configuración
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-3-haiku-20240307")

# Configurar Claude si está disponible
if CLAUDE_AVAILABLE and CLAUDE_API_KEY and CLAUDE_API_KEY != "your_claude_api_key_here":
    try:
        client = Anthropic(api_key=CLAUDE_API_KEY)
        print(f"✅ Claude configurado correctamente con modelo: {CLAUDE_MODEL}")
    except Exception as e:
        print(f"❌ Error al configurar Claude: {e}")
        CLAUDE_AVAILABLE = False
elif not CLAUDE_API_KEY or CLAUDE_API_KEY == "your_claude_api_key_here":
    print("⚠️ CLAUDE_API_KEY no configurada. Usando modo fallback.")
    CLAUDE_AVAILABLE = False
else:
    print("⚠️ Claude no disponible. Usando modo fallback.")
    CLAUDE_AVAILABLE = False


def create_analysis_prompt(url, vt_result, heuristic_result, identity_result=None):
    """
    Crea un prompt avanzado para análisis inteligente con IA.
    """
    from urllib.parse import urlparse
    
    # Extraer datos de VirusTotal
    vt_status = vt_result.get("status", "unknown")
    vt_malicious = vt_result.get("stats", {}).get("malicious", 0)
    vt_suspicious = vt_result.get("stats", {}).get("suspicious", 0)
    vt_harmless = vt_result.get("stats", {}).get("harmless", 0)
    vt_undetected = vt_result.get("stats", {}).get("undetected", 0)
    vt_engines = vt_result.get("detection_engines", [])
    vt_categories = vt_result.get("categories", [])
    
    # Extraer datos heurísticos
    heur_score = heuristic_result.get("score", 0)
    heur_level = heuristic_result.get("risk_level", "BAJO")
    heur_reasons = heuristic_result.get("reasons", [])
    heur_indicators = heuristic_result.get("total_indicators", 0)
    
    # Analizar la URL para contexto
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        scheme = parsed.scheme
        has_params = bool(parsed.query)
    except:
        domain = "desconocido"
        path = ""
        scheme = "http"
        has_params = False
    
    # Extraer datos de Identidad
    identity_status = identity_result.get("status", "unknown") if identity_result else "unknown"
    identity_name = identity_result.get("name", "") if identity_result else ""
    identity_reason = identity_result.get("reason", "") if identity_result else ""
    
    prompt = f"""Eres un analista experto en ciberseguridad con especialización en phishing, ingeniería social y análisis forense de URLs. Tu tarea es proporcionar un análisis INTELIGENTE y CONTEXTUAL, no solo resumir datos.

**URL A ANALIZAR:**
{url}

**DATOS TÉCNICOS:**

VirusTotal:
- Malicioso: {vt_malicious} | Sospechoso: {vt_suspicious} | Inofensivo: {vt_harmless} | Sin detectar: {vt_undetected}
""" + (f"- Motores alertando: {', '.join(vt_engines[:5])}" if vt_engines else "") + f"""
""" + (f"- Categorías: {', '.join(vt_categories)}" if vt_categories else "") + f"""

Heurístico:
- Score: {heur_score}/100 (Nivel: {heur_level})
- Indicadores: {heur_indicators}
""" + "\n".join([f"  • {reason}" for reason in heur_reasons[:5]]) + f"""

**ESTADO DE IDENTIDAD (MOTOR VIP):**
- Estado: {identity_status.upper()}
""" + (f"- Nombre Confirmado: {identity_name}\n- Razón: {identity_reason}" if identity_status == "verified" else f"- Alerta: {identity_reason}" if identity_status == "impersonation" else "- El dominio es desconocido para el motor de identidad.") + f"""

**TU MISIÓN COMO ANALISTA INTELIGENTE:**

1. **ANÁLISIS DE PATRONES**: Examina la estructura de la URL (dominio: "{domain}", path: "{path}", protocolo: {scheme}). Identifica:
   - Typosquatting (dominios similares a marcas conocidas)
   - Homógrafos (caracteres que se ven iguales pero no lo son)
   - Subdominios sospechosos o excesivos
   - Uso de números, guiones o caracteres especiales estratégicos
   - Extensiones de dominio inusuales (.tk, .ml, etc.)

2. **TÉCNICAS DE INGENIERÍA SOCIAL**: Detecta palabras o patrones psicológicos:
   - Urgencia: "urgent", "verify", "suspend", "limited time"
   - Autoridad: "security", "official", "account", "confirm"
   - Miedo: "blocked", "unauthorized", "suspicious activity"
   - Recompensa: "prize", "reward", "claim", "free"

3. **CONTEXTO Y PSICOLOGÍA**: Explica:
   - ¿Por qué un usuario promedio podría caer en esto?
   - ¿Qué táctica específica usa el atacante?
   - ¿A qué tipo de servicio legítimo intenta imitar?

4. **ANÁLISIS PROFUNDO**: No te limites a decir "X motores lo detectaron". Explica:
   - ¿Qué hace a esta URL peligrosa ESPECÍFICAMENTE?
   - ¿Qué información podría robar el atacante?
   - ¿Qué consecuencias reales tendría caer en este ataque?

**IMPORTANTE - CRITERIOS DE EVALUACIÓN:**
- **ESTADO DE IDENTIDAD (MOTOR VIP)**: Si el estado es **IMPERSONATION**, el riesgo DEBE ser **Crítico**. Si el sistema ya detectó una suplantación, tu trabajo es COCORROBORARLO y explicar el peligro, NUNCA decir que es seguro.
- **TOLERANCIA CERO A LA SUPLANTACIÓN**: Si identificas Typosquatting (ej: `outl3` en lugar de `outlook`), el riesgo DEBE ser **Alto** o **Crítico**. No digas "no es malicioso" si hay engaño visual.
- **CONSERVADURISMO CONDICIONAL**: Solo sé conservador si el dominio es **Seguro** o **Desconocido** Y no hay rasgos de ingeniería social. Si hay suplantación detectada por el motor de identidad, el conservadurismo NO APLICA.
- **FALSOS POSITIVOS**: No marques como peligrosos dominios legítimos oficiales (google.com, microsoft.com), pero sé implacable con dominios sospechosos en hostings gratuitos (webcindario, vercel).
- **COHERENCIA CRÍTICA**: Si mencionas conceptos como "atacante", "phishing", "robo de datos", "suplantación" o "téctica maliciosa", el RIESGO NO PUEDE SER BAJO NI MEDIO. Debe ser **Alto** o **Crítico**.

**FORMATO DE RESPUESTA (EXACTO):**

ANÁLISIS:
[2-3 oraciones con análisis INTELIGENTE y CONTEXTUAL. Si es seguro, dilo claramente como "SEGURO" o "VERIFICADO". Si es dudoso, explica por qué sin ser alarmista.]

RIESGO: [Bajo/Medio/Alto/Crítico]

RECOMENDACIONES:
• [Recomendación específica]
• [Si es seguro: "Verificar certificado HTTPS"]
• [Si es sospechoso: "No ingresar datos personales"]
"""
    
    return prompt


def parse_ai_response(response_text):
    """
    Parsea la respuesta de la IA en un formato estructurado.
    """
    try:
        lines = response_text.strip().split('\n')
        
        analysis = ""
        risk = "Medio"
        recommendations = []
        
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("ANÁLISIS:"):
                current_section = "analysis"
                analysis = line.replace("ANÁLISIS:", "").strip()
            elif line.startswith("RIESGO:"):
                current_section = "risk"
                risk = line.replace("RIESGO:", "").strip()
            elif line.startswith("RECOMENDACIONES:"):
                current_section = "recommendations"
            elif line.startswith("•") or line.startswith("-"):
                if current_section == "recommendations":
                    recommendations.append(line.lstrip("•-").strip())
            elif current_section == "analysis" and line:
                analysis += " " + line
            elif current_section == "recommendations" and line:
                if not line.startswith("RIESGO") and not line.startswith("ANÁLISIS"):
                    recommendations.append(line)
        
        return {
            "analysis": analysis.strip(),
            "risk_level": risk.strip(),
            "recommendations": [r for r in recommendations if r]
        }
    
    except Exception as e:
        print(f"❌ Error al parsear respuesta de IA: {e}")
        return {
            "analysis": response_text,
            "risk_level": "Medio",
            "recommendations": ["Procede con precaución al visitar esta URL."]
        }


def analyze_with_ai(url, vt_result, heuristic_result, identity_result=None):
    """
    Analiza la URL usando IA (Claude) con los resultados de VirusTotal, análisis heurístico e identidad.
    """
    
    # Si Claude no está disponible, usar fallback
    if not CLAUDE_AVAILABLE:
        return generate_fallback_analysis(url, vt_result, heuristic_result, identity_result)
    
    try:
        # Crear el prompt
        prompt = create_analysis_prompt(url, vt_result, heuristic_result, identity_result)
        
        # Generar análisis con Claude
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=1024,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        # Extraer texto de la respuesta
        response_text = message.content[0].text
        
        # Parsear la respuesta
        parsed = parse_ai_response(response_text)
        
        print(f"✅ Análisis con IA completado para: {url}")
        
        return {
            "status": "success",
            "ai_analysis": parsed["analysis"],
            "ai_risk_level": parsed["risk_level"],
            "ai_recommendations": parsed["recommendations"],
            "source": "claude"
        }
    
    except Exception as e:
        print(f"❌ Error al analizar con IA: {e}")
        # Fallback en caso de error
        return generate_fallback_analysis(url, vt_result, heuristic_result)


def generate_fallback_analysis(url, vt_result, heuristic_result, identity_result=None):
    """
    Genera un análisis detallado y contextual cuando la IA no está disponible.
    """
    from urllib.parse import urlparse

    # Si está verificado por identidad, el riesgo es Bajo automáticamente
    if identity_result and identity_result.get("status") == "verified":
        return {
            "status": "success",
            "ai_analysis": f"✅ **Identidad Confirmada**: Esta URL pertenece oficialmente a **{identity_result.get('name')}**. El análisis técnico confirma que es el sitio legítimo.",
            "ai_risk_level": "Bajo",
            "ai_recommendations": ["✅ Puedes navegar con total confianza", "🔒 Verifica siempre el candado de seguridad"],
            "source": "identity_override"
        }
    
    vt_status = vt_result.get("status", "unknown")
    vt_malicious = vt_result.get("stats", {}).get("malicious", 0)
    vt_suspicious = vt_result.get("stats", {}).get("suspicious", 0)
    vt_harmless = vt_result.get("stats", {}).get("harmless", 0)
    vt_engines = vt_result.get("detection_engines", [])
    vt_categories = vt_result.get("categories", [])
    
    heur_score = heuristic_result.get("score", 0)
    heur_level = heuristic_result.get("risk_level", "BAJO")
    heur_indicators = heuristic_result.get("reasons", [])
    heur_count = heuristic_result.get("total_indicators", 0)
    
    # Extraer dominio para análisis
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
    except:
        domain = "la URL"
    
    # Determinar nivel de riesgo combinado
    total_threats = vt_malicious + vt_suspicious
    
    # Construir análisis contextual
    analysis_parts = []
    
    # === NIVEL CRÍTICO ===
    if total_threats >= 5 or heur_score >= 60:
        risk_level = "Crítico"
        
        # Introducción alarmante
        analysis_parts.append(f"🚨 **ALERTA MÁXIMA**: Esta URL representa una amenaza seria y confirmada.")
        
        # VirusTotal
        if total_threats >= 5:
            engines_text = f" ({', '.join(vt_engines[:3])}{'...' if len(vt_engines) > 3 else ''})" if vt_engines else ""
            analysis_parts.append(f"**{total_threats} motores de seguridad** la identificaron como peligrosa{engines_text}, indicando un consenso claro sobre su naturaleza maliciosa.")
        
        # Categorías
        if vt_categories:
            cat_text = ', '.join(vt_categories[:3])
            analysis_parts.append(f"Se clasificó como: **{cat_text}**.")
        
        # Análisis heurístico
        if heur_score >= 60:
            analysis_parts.append(f"El análisis heurístico obtuvo **{heur_score}/100 puntos** (nivel {heur_level}), detectando {heur_count} indicadores críticos:")
            for i, indicator in enumerate(heur_indicators[:3], 1):
                analysis_parts.append(f"  {i}. {indicator}")
            if len(heur_indicators) > 3:
                analysis_parts.append(f"  ... y {len(heur_indicators) - 3} indicadores más.")
        
        # Contexto
        analysis_parts.append(f"\n**¿Por qué es peligroso?** Los sitios de phishing buscan robar tus credenciales haciéndose pasar por servicios legítimos. El dominio '{domain}' presenta múltiples características de estos ataques.")
        
        recommendations = [
            "🚫 NO visites esta URL bajo ninguna circunstancia",
            "🔒 NO ingreses contraseñas, datos bancarios o información personal",
            "📧 Si recibiste esto por email, repórtalo como spam/phishing",
            "⚠️ Alerta a otros si compartieron esta URL contigo",
            "🛡️ Considera cambiar contraseñas si ya visitaste este sitio"
        ]
    
    # === NIVEL ALTO (Aumentado por palabras clave sociales) ===
    elif total_threats >= 2 or heur_score >= 40 or any(word in url.lower() for word in ["secure", "login", "verify", "account", "bank"]):
        risk_level = "Alto"
        
        analysis_parts.append(f"⚠️ Esta URL presenta **señales claras de riesgo** que sugieren actividad maliciosa o phishing.")
        
        # VirusTotal
        if total_threats >= 2:
            engines_text = f" (incluyendo {', '.join(vt_engines[:2])})" if vt_engines else ""
            analysis_parts.append(f"**{total_threats} motores de seguridad** reportaron actividad sospechosa{engines_text}.")
        
        # Categorías
        if vt_categories:
            analysis_parts.append(f"Categorizada como: **{vt_categories[0]}**.")
        
        # Análisis heurístico
        if heur_score >= 40:
            analysis_parts.append(f"\nEl análisis heurístico identificó **{heur_count} patrones sospechosos** (score: {heur_score}/100):")
            for indicator in heur_indicators[:2]:
                analysis_parts.append(f"  • {indicator}")
            if len(heur_indicators) > 2:
                analysis_parts.append(f"  • ... y {len(heur_indicators) - 2} más")
        
        # Contexto específico
        if any("login" in ind.lower() or "verify" in ind.lower() or "account" in ind.lower() for ind in heur_indicators):
            analysis_parts.append(f"\n**Riesgo de phishing**: El uso de términos como 'login', 'verify' o 'account' es común en ataques que intentan robar credenciales.")
        
        if any("número" in ind.lower() or "guion" in ind.lower() for ind in heur_indicators):
            analysis_parts.append(f"**Dominio sospechoso**: Los atacantes suelen usar dominios con números o guiones excesivos para imitar sitios legítimos.")
        
        recommendations = [
            "🛑 Evita visitar esta URL",
            "🔍 Verifica la legitimidad del sitio por otros medios (contacto oficial)",
            "📧 Si llegó por email, verifica el remitente real (no solo el nombre)",
            "🚫 No descargues archivos ni ejecutes nada de esta página",
            "💡 Si necesitas acceder al servicio, usa la URL oficial directa"
        ]
    
    # === NIVEL MEDIO ===
    elif total_threats >= 1 or heur_score >= 20:
        risk_level = "Medio"
        
        analysis_parts.append(f"⚡ Esta URL muestra **algunos indicadores de precaución** que merecen atención.")
        
        # VirusTotal
        if total_threats == 1:
            engine_name = vt_engines[0] if vt_engines else "un motor de seguridad"
            analysis_parts.append(f"**{engine_name}** la reportó como potencialmente peligrosa, aunque otros motores no coinciden.")
        
        # Análisis heurístico
        if heur_score >= 20:
            analysis_parts.append(f"\nEl análisis heurístico detectó **{heur_count} señales de alerta** (score: {heur_score}/100):")
            for indicator in heur_indicators[:2]:
                analysis_parts.append(f"  • {indicator}")
        
        # Contexto
        analysis_parts.append(f"\n**Análisis**: Aunque no hay consenso de que sea maliciosa, el dominio '{domain}' presenta características que requieren verificación antes de confiar.")
        
        if heur_score < 20 and total_threats == 1:
            analysis_parts.append("Es posible que sea un falso positivo, pero la precaución nunca está de más.")
        
        recommendations = [
            "⚠️ Procede con cautela y verifica la legitimidad",
            "🔍 Confirma que el dominio coincide con el servicio oficial",
            "🚫 No ingreses información sensible sin estar seguro",
            "💳 Evita realizar transacciones o pagos",
            "📞 Si es de un servicio conocido, contacta por vía oficial"
        ]
    
    # === NIVEL BAJO ===
    else:
        risk_level = "Bajo"
        
        total_scans = vt_harmless + vt_malicious + vt_suspicious + vt_result.get("stats", {}).get("undetected", 0)
        
        analysis_parts.append(f"✅ **Buenas noticias**: No detectamos amenazas significativas en esta URL.")
        
        if total_scans > 0:
            analysis_parts.append(f"\n**{vt_harmless} de {total_scans} motores** de VirusTotal la clasificaron como inofensiva.")
        
        if heur_score > 0:
            analysis_parts.append(f"El análisis heurístico encontró {heur_count} señales menores (score: {heur_score}/100), pero ninguna crítica.")
        else:
            analysis_parts.append("El análisis heurístico no encontró patrones sospechosos.")
        
        analysis_parts.append(f"\n**Importante**: La ausencia de alertas no garantiza seguridad al 100%. Mantén siempre prácticas seguras de navegación.")
        
        recommendations = [
            "✅ Es seguro, puedes navegar con confianza",
            "🔒 Asegúrate de que use HTTPS (candado en el navegador)",
            "🛡️ Mantén tu navegador y antivirus actualizados",
            "💡 Si algo te parece extraño en el sitio, no continues",
            "📧 Ten cuidado con solicitudes inesperadas de información personal"
        ]
    
    # Unir todas las partes del análisis
    full_analysis = " ".join(analysis_parts)
    
    return {
        "status": "success",
        "ai_analysis": full_analysis,
        "ai_risk_level": risk_level,
        "ai_recommendations": recommendations,
        "source": "fallback"
    }
