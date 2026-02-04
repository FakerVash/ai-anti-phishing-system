# Guía Rápida: Configurar Claude API

## 🚀 Pasos para obtener tu API Key de Claude

### 1. **Crear cuenta en Anthropic**
   - Ve a: **https://console.anthropic.com/**
   - Click en **"Sign Up"**
   - Usa tu email para registrarte

### 2. **Verificar tu email**
   - Revisa tu bandeja de entrada
   - Click en el link de verificación

### 3. **Agregar método de pago**
   - Una vez dentro del panel, ve a **"Billing"**
   - Click en **"Add payment method"**
   - Ingresa los datos de tu tarjeta de crédito/débito
   - ⚠️ **No te cobrarán nada aún**, solo lo guardan para facturación

### 4. **Establecer límite de gasto (IMPORTANTE)**
   - En **"Billing" → "Usage limits"**
   - Establece un límite mensual (recomendado: **$10-20**)
   - Esto evita sorpresas en la factura

### 5. **Obtener API Key**
   - Ve a **"API Keys"** en el menú lateral
   - Click en **"Create Key"**
   - Dale un nombre (ej: "anti-phishing-system")
   - **COPIA LA CLAVE** (solo se muestra una vez)

### 6. **Configurar en tu sistema**
   - Abre el archivo: `backend/.env`
   - Reemplaza la línea:
     ```
     CLAUDE_API_KEY=your_claude_api_key_here
     ```
   - Por:
     ```
     CLAUDE_API_KEY=sk-ant-api03-XXXXXXXXXXXXXXXXX
     ```
   - (Usa tu clave real que copiaste)

### 7. **Reiniciar el servidor**
   - Detén el servidor actual (Ctrl+C)
   - Ejecuta de nuevo:
     ```bash
     python app.py
     ```
   - Deberías ver:
     ```
     ✅ Claude configurado correctamente con modelo: claude-3-haiku-20240307
     ```

---

## 💰 Precios de Claude Haiku

- **Entrada**: $0.25 por millón de tokens
- **Salida**: $1.25 por millón de tokens

**Estimación para tu uso:**
- 100 análisis = ~$0.01-0.05
- 1,000 análisis = ~$0.13-0.63
- 10,000 análisis = ~$1.30-6.30

---

## ✅ Verificar que funciona

1. Ve a: http://localhost:5000/health
2. Deberías ver:
   ```json
   {
     "status": "healthy",
     "services": {
       "claude": "configured",
       "virustotal": "configured",
       "heuristic": "active"
     }
   }
   ```

3. Prueba con una URL:
   - http://localhost:5000
   - Ingresa: `https://example-phishing-site.com`
   - Deberías ver análisis generado por Claude

---

## 🔧 Modelos disponibles

En el archivo `.env` puedes cambiar el modelo:

```env
# Más barato y rápido (recomendado)
CLAUDE_MODEL=claude-3-haiku-20240307

# Balance precio/calidad
CLAUDE_MODEL=claude-3-5-sonnet-20241022

# Más potente pero caro
CLAUDE_MODEL=claude-3-opus-20240229
```

---

## ⚠️ Solución de Problemas

### Error: "Invalid API Key"
- Verifica que copiaste la clave completa
- Asegúrate de que no hay espacios al inicio/final
- La clave debe comenzar con `sk-ant-`

### Error: "Insufficient credits"
- Verifica que agregaste método de pago
- Revisa límites en el panel de Anthropic

### No aparece análisis con IA
- Revisa la consola del servidor
- Debería mostrar: `✅ Claude configurado correctamente`
- Si dice "modo fallback", verifica la API key

---

## 📊 Monitorear Uso

Para ver cuánto has gastado:
1. Ve a https://console.anthropic.com/
2. Click en **"Usage"**
3. Verás gráficas de:
   - Tokens consumidos
   - Costo acumulado
   - Solicitudes por día

---

¡Listo! Una vez que tengas tu API key, el sistema estará completamente funcional con análisis inteligente de Claude. 🚀
