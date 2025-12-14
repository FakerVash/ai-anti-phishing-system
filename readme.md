# 🛡️ Sistema Anti-Phishing Inteligente con IA

Proyecto académico que implementa un **Sistema Anti-Phishing Inteligente** capaz de analizar URLs y determinar si corresponden a sitios de phishing conocidos, utilizando una **base de datos real (PhishTank)**, un **servidor web en Flask** y un **módulo de Inteligencia Artificial explicativa**.

El sistema está diseñado para ejecutarse inicialmente en **Windows** y posteriormente desplegarse en **Kali Linux**, manteniendo la portabilidad mediante control de versiones con Git.

---

## 🎯 Objetivo del Proyecto

Desarrollar un sistema que permita:

* Analizar URLs ingresadas por el usuario.
* Detectar si una URL corresponde a phishing.
* Mostrar información clara y comprensible sobre el resultado.
* Apoyarse en Inteligencia Artificial para explicar los resultados.

---

## 🧠 Tecnologías Utilizadas

* **Python 3**
* **Flask** – Servidor web
* **Pandas** – Procesamiento de datos
* **PhishTank** – Base de datos de URLs phishing verificadas
* **HTML, CSS, JavaScript** – Interfaz web
* **Jinja2** – Renderizado de plantillas

---

## 🗂️ Fuente de Datos (PhishTank)

Se utiliza la base de datos pública de **PhishTank**, la cual registra URLs de phishing verificadas por la comunidad.

Columnas utilizadas del dataset:

* `url`
* `target`
* `phish_detail_url`

Estos datos permiten identificar el sitio malicioso y la entidad suplantada.

---

## ⚙️ Arquitectura del Sistema

1. El usuario ingresa una URL desde la interfaz web.
2. El servidor Flask recibe la solicitud.
3. Se consulta la base de datos PhishTank.
4. El sistema determina si la URL es phishing o segura.
5. Un módulo de IA genera una explicación del resultado.
6. El resultado se muestra en la interfaz.

---

## 🤖 Uso de Inteligencia Artificial

El sistema integra un **módulo de IA explicativa**, encargado de:

* Interpretar los resultados del análisis.
* Generar explicaciones comprensibles para el usuario.
* Asistir conceptualmente en análisis, debugging y mejora del sistema.

La arquitectura está preparada para conectarse en el futuro con servicios externos como **ChatGPT mediante API**, permitiendo un análisis más avanzado y respuestas inteligentes.

---

## 🎨 Interfaz y Paleta de Colores

La interfaz fue diseñada con una estética orientada a ciberseguridad, usando la siguiente paleta:

* `#AC00BF` – Púrpura intenso
* `#6A3571` – Violeta oscuro
* `#9000A1` – Púrpura profundo
* `#FFE9FF` – Rosa pálido (texto principal)
* `#865D8A` – Malva apagado
* `#DEBBE2` – Lila suave

---

## 🚀 Ejecución del Proyecto

### 1️⃣ Instalar dependencias

```bash
python -m pip install -r requirements.txt
```

### 2️⃣ Ejecutar el servidor

```bash
python app.py
```

El servidor se iniciará en:

```
http://127.0.0.1:5000
```

---

## 📌 Ejemplo de Resultado

Cuando una URL es detectada como phishing:

```
🚨 PHISHING DETECTADO
Objetivo: Other
Ver detalle en PhishTank
```

Incluyendo una explicación generada por el módulo de IA.

---

## 🧪 Estado del Proyecto

* ✔ Base de datos PhishTank integrada
* ✔ Servidor Flask funcional
* ✔ Interfaz web operativa
* ✔ IA explicativa integrada (conceptual)
* ✔ Preparado para despliegue en Kali Linux

---

## 🔮 Trabajo Futuro

* Integración con API de VirusTotal
* Integración real con ChatGPT mediante API
* Historial de URLs analizadas
* Clasificación por nivel de riesgo
* Despliegue en servidor productivo

---


🛡️ *Proyecto académico desarrollado con fines educativos y de concienciación en ciberseguridad.*
