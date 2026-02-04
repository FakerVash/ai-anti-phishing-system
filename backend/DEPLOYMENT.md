# 🚀 Guía de Deployment a Render

## 📋 Requisitos Previos

1. **Cuenta de Render**: Crea una cuenta gratuita en https://render.com
2. **Cuenta de GitHub** (opcional pero recomendado)
3. **API Keys**:
   - VirusTotal: Ya la tienes
   - Claude (Anthropic): Ya la tienes

---

## 🎯 Método Recomendado: GitHub + Render

### **Paso 1: Subir a GitHub**

1. **Crear repositorio en GitHub:**
   - Ve a https://github.com/new
   - Nombre: `ai-anti-phishing-system`
   - Público o Privado (tu elección)
   - Click en "Create repository"

2. **Subir tu código:**
   ```bash
   cd "c:\Users\usuar\Downloads\Proyecto AI\ai-anti-phishing-system\backend"
   
   # Inicializar Git
   git init
   git add .
   git commit -m "Initial commit: AI Anti-Phishing System"
   
   # Conectar con GitHub (reemplaza con tu URL)
   git remote add origin https://github.com/TU-USUARIO/ai-anti-phishing-system.git
   git branch -M main
   git push -u origin main
   ```

---

### **Paso 2: Desplegar en Render**

1. **Ir a Render:**
   - Ve a https://dashboard.render.com/
   - Click en "New +" → "Web Service"

2. **Conectar GitHub:**
   - Autoriza a Render para acceder a tu GitHub
   - Selecciona el repositorio `ai-anti-phishing-system`

3. **Configurar el servicio:**
   ```
   Name: ai-phishing-detector
   Region: Oregon (US West) o el más cercano
   Branch: main
   Root Directory: backend (IMPORTANTE)
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: gunicorn app:app
   ```

4. **Plan:**
   - Selecciona: **Free** ($0/mes)
   - Limitaciones: 750 horas/mes (suficiente para pruebas)

5. **Variables de Entorno (Environment Variables):**
   Click en "Advanced" → "Add Environment Variable"
   
   Agrega estas 3 variables:
   ```
   VT_API_KEY = e1cf8be4e0805750ba6194e6ab415b0354a72aa364c42bfcce48ce9c78160f57
   CLAUDE_API_KEY = tu_api_key_de_claude_aqui
   CLAUDE_MODEL = claude-3-haiku-20240307
   ```

6. **Crear servicio:**
   - Click en "Create Web Service"
   - Render comenzará a desplegar (toma 3-5 minutos)

---

### **Paso 3: Verificar que Funciona**

Una vez que el deployment termine, Render te dará una URL:
```
https://ai-phishing-detector.onrender.com
```

**Prueba el sistema:**

1. **Health Check:**
   ```
   https://tu-app.onrender.com/health
   ```
   Deberías ver:
   ```json
   {
     "status": "healthy",
     "services": {
       "virustotal": "configured",
       "claude": "configured",
       "heuristic": "active"
     }
   }
   ```

2. **Analizar URL:**
   ```
   https://tu-app.onrender.com/check?url=https://google.com
   ```

3. **Interfaz web:**
   ```
   https://tu-app.onrender.com/
   ```

---

## 🔧 Archivos Importantes Creados

### **1. Procfile**
Define cómo ejecutar la app en producción:
```
web: gunicorn app:app
```

### **2. requirements.txt actualizado**
Ahora incluye:
- `gunicorn` - Servidor WSGI para producción
- `flask-cors` - Permite requests desde otros dominios

### **3. app.py con CORS**
Permite que tu API sea llamada desde:
- Tu extensión de navegador
- Otros sitios web
- Postman/curl

---

## ⚠️ Limitaciones del Plan Gratuito

**Render Free Tier:**
- ✅ 750 horas/mes (31 días × 24h = suficiente)
- ⚠️ El servicio se "duerme" después de 15 min inactivo
- ⚠️ Primera request post-sleep tarda ~30 segundos
- ✅ 100GB de ancho de banda/mes

**Soluciones:**
1. Usar un pinger (como UptimeRobot) para mantenerlo activo
2. Upgrade a plan de $7/mes para 24/7 sin sleep

---

## 💰 Costos Estimados

| Servicio | Plan | Costo |
|----------|------|-------|
| **Render** | Free | $0 |
| **Claude** | Pay-as-you-go | ~$2-5/mes |
| **VirusTotal** | Free | $0 |
| **Total** | | **$2-5/mes** |

---

## 🎯 Próximos Pasos (Opcional)

### **1. Dominio Personalizado:**
En lugar de `ai-phishing-detector.onrender.com`, usa:
```
api.tudominio.com
```
- Costo: $10-15/año (Namecheap, GoDaddy)

### **2. Monitoreo:**
- Configurar UptimeRobot (gratis) para ping cada 5 minutos
- Evita que el servicio se duerma

### **3. Analytics:**
- Agregar Google Analytics
- Ver cuántas consultas recibes

---

## 🐛 Solución de Problemas

### **Error: "Application failed to start"**
- Revisa los logs en Render Dashboard
- Verifica que `Procfile` esté en `backend/`
- Confirma que `requirements.txt` tenga gunicorn

### **Error: "Module not found"**
- Asegúrate de que Root Directory = `backend`
- Re-deploya después de cambios

### **Claude no funciona:**
- Verifica la variable `CLAUDE_API_KEY` en Environment
- Revisa logs del servidor

### **CORS errors:**
- Ya está configurado en `app.py`
- Si persiste, agrega tu dominio específico

---

## ✅ Checklist de Deployment

- [ ] Código subido a GitHub
- [ ] Servicio creado en Render
- [ ] Variables de entorno configuradas
- [ ] Deployment exitoso (verde)
- [ ] `/health` responde correctamente
- [ ] `/check` funciona con URLs de prueba
- [ ] Interfaz web carga correctamente

---

## 🚀 Una Vez Deployado

Tu API estará disponible en:
```
https://tu-app.onrender.com/check
```

Podrás usarla desde:
- ✅ Tu extensión de navegador
- ✅ Otros servicios/apps
- ✅ Postman/curl para testing
- ✅ La interfaz web visual

---

¡Listo para deployment! 🎉
