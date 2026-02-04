# Sistema Anti-Phishing con IA Mejorado

Sistema avanzado de detección de phishing que combina análisis heurístico, VirusTotal y Google Gemini para proporcionar análisis inteligentes y detallados.

## 🚀 Características

### 1. **Análisis Heurístico Avanzado** (`detector.py`)
- ✅ Detección de 12+ indicadores de phishing
- ✅ Análisis de entropía para detectar dominios aleatorios
- ✅ Detección de URL shorteners
- ✅ Identificación de direcciones IP en lugar de dominios
- ✅ Análisis de subdominios excesivos
- ✅ Detección de extensiones de archivo peligrosas
- ✅ Puntuación de riesgo 0-100

### 2. **Integración con VirusTotal** (`virustotal_service.py`)
- ✅ Análisis con 90+ motores de seguridad
- ✅ Captura de motores que detectaron amenazas
- ✅ Categorización de tipos de amenazas
- ✅ Sistema de reintentos automáticos
- ✅ Manejo robusto de errores

### 3. **Análisis con IA - Google Gemini** (`ai_analyzer.py`)
- ✅ Prompts estructurados profesionales
- ✅ Análisis contextual inteligente
- ✅ Recomendaciones personalizadas
- ✅ Sistema de fallback cuando la API no está disponible
- ✅ Parsing estructurado de respuestas

### 4. **Pipeline Unificado** (`app.py`)
- ✅ Integración de los 3 sistemas de análisis
- ✅ Respuesta JSON estructurada y completa
- ✅ Endpoint de health check
- ✅ Validación robusta de URLs

## 📋 Requisitos

```
flask
pandas
requests
python-dotenv
google-generativeai
urllib3
certifi
```

## 🔧 Configuración

### 1. Clonar/Descargar el proyecto

### 2. Instalar dependencias
```bash
cd backend
pip install -r requirements.txt
```

### 3. Configurar API Keys

Edita el archivo `.env`:

```env
VT_API_KEY=tu_api_key_de_virustotal
GEMINI_API_KEY=tu_api_key_de_gemini
GEMINI_MODEL=gemini-1.5-flash
```

**Obtener API Keys:**
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **Google Gemini**: https://aistudio.google.com/app/apikey

## 🏃‍♂️ Ejecución

```bash
python app.py
```

El servidor se ejecutará en `http://localhost:5000`

## 📡 API Endpoints

### 1. **POST /check** - Analizar URL

**Request:**
```json
{
  "url": "https://ejemplo.com"
}
```

**Response:**
```json
{
  "status": "suspicious",
  "url": "https://ejemplo.com",
  
  "ai_analysis": "Esta URL presenta algunos indicadores...",
  "ai_risk_level": "Medio",
  "ai_recommendations": [
    "Procede con precaución extrema",
    "Verifica que la URL sea legítima",
    "No ingreses información sensible"
  ],
  
  "heuristic": {
    "score": 45,
    "risk_level": "ALTO",
    "indicators": [
      "Uso excesivo de guiones en el dominio",
      "Palabras de phishing detectadas: login, verify"
    ],
    "total_indicators": 2
  },
  
  "virustotal": {
    "status": "suspicious",
    "risk_score": 50,
    "stats": {
      "malicious": 3,
      "suspicious": 2,
      "harmless": 85,
      "undetected": 0
    },
    "detection_engines": ["Kaspersky", "Avira", "ESET"],
    "categories": ["phishing"],
    "analysis_url": "https://www.virustotal.com/api/v3/analyses/..."
  },
  
  "metadata": {
    "ai_source": "gemini",
    "timestamp": null
  }
}
```

### 2. **GET /health** - Estado del sistema

**Response:**
```json
{
  "status": "healthy",
  "services": {
    "virustotal": "configured",
    "gemini": "configured",
    "heuristic": "active"
  }
}
```

## 🧪 Pruebas

### URLs de Prueba

1. **URL Segura:**
```bash
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

2. **URL con Indicadores Heurísticos:**
```bash
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://secure-login-verify-account-12345.suspicious-domain.com/update"}'
```

## 📊 Niveles de Riesgo

| Nivel | Score Heurístico | Detecciones VT | Descripción |
|-------|-----------------|----------------|-------------|
| **BAJO** | 0-19 | 0 | Sin amenazas detectadas |
| **MEDIO** | 20-39 | 1 | Algunos indicadores sospechosos |
| **ALTO** | 40-59 | 2-4 | Múltiples indicadores de riesgo |
| **CRÍTICO** | 60-100 | 5+ | Amenaza confirmada por múltiples fuentes |

## 🔍 Indicadores Heurísticos Detectados

1. **Guiones excesivos** - Dominios con 3+ guiones
2. **Números largos** - Secuencias de 4+ dígitos
3. **Palabras de phishing** - login, verify, bank, etc.
4. **URLexcesivamente larga** - Más de 100 caracteres
5. **URL shorteners** - bit.ly, tinyurl.com, etc.
6. **Extensiones peligrosas** - .exe, .zip, .scr, etc.
7. **Direcciones IP** - Uso de IP en lugar de dominio
8. **Subdominios excesivos** - Más de 3 niveles
9. **Alta entropía** - Dominios aleatorios generados
10. **Patrones sospechosos** - @, doble //, etc.
11. **HTTP no seguro** - Sin HTTPS
12. **Caracteres especiales** - Exceso de símbolos

## 🤖 Sistema de IA

El sistema utiliza **Google Gemini (gemini-1.5-flash)** con prompts estructurados que:

1. **Analizan** resultados de VirusTotal y análisis heurístico
2. **Interpretan** patrones y comportamientos sospechosos
3. **Generan** explicaciones claras para usuarios no técnicos
4. **Recomiendan** acciones específicas según el nivel de riesgo

### Ejemplo de Prompt:
```
Eres un experto en ciberseguridad...

URL Analizada: https://ejemplo.com
Resultados de VirusTotal: ...
Análisis Heurístico: ...

Proporciona:
1. Análisis claro (2-3 oraciones)
2. Nivel de riesgo (Bajo/Medio/Alto/Crítico)
3. Recomendaciones específicas
```

## 🔄 Sistema de Fallback

Si la API de Gemini no está disponible o configurada:
- ✅ El sistema sigue funcionando
- ✅ Utiliza análisis estático basado en reglas
- ✅ Proporciona recomendaciones predefinidas
- ✅ No interrumpe el flujo de análisis

## 📝 Notas Importantes

- **API de Gemini**: Tiene límite de 15 solicitudes/minuto en capa gratuita
- **VirusTotal**: El análisis puede tardar 15-20 segundos
- **Caché**: Considera implementar caché para URLs frecuentes
- **Rate Limiting**: Implementa límites si expones públicamente

## 🐛 Troubleshooting

### Error: "GEMINI_API_KEY no configurada"
- Verifica que el `.env` tenga la API key correcta
- Asegúrate de que no sea `your_gemini_api_key_here`

### Error: "VT_API_KEY no está configurada"
- Obtén una API key gratuita en VirusTotal
- Agrégala al archivo `.env`

### Error: "google-generativeai no está instalado"
- Ejecuta: `pip install google-generativeai`

## 🎯 Mejoras Futuras Sugeridas

- [ ] Implementar caché con Redis
- [ ] Agregar análisis de certificados SSL
- [ ] Integrar más fuentes de inteligencia de amenazas
- [ ] Crear dashboard visual con estadísticas
- [ ] Implementar rate limiting por IP
- [ ] Agregar análisis de contenido de la página
- [ ] Sistema de reportes y alertas
- [ ] Integración con APIs de reputación de dominios

## 📄 Licencia

Este proyecto es de código abierto y está disponible para uso educativo.

## 👨‍💻 Autor

Sistema creado para detección avanzada de phishing con IA.
