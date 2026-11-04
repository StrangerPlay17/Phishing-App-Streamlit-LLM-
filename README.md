# Phishing Detector AI

Aplicación desarrollada en Python para analizar URL potencialmente relacionadas con ataques de phishing.

El sistema combina análisis heurístico, consultas a Google Safe Browsing y modelos de lenguaje (LLM) para evaluar las URL y proporcionar explicaciones y recomendaciones de seguridad.

## Requisitos previos

Antes de ejecutar el proyecto, es necesario contar con:

- Python 3.10 o superior.
- Git.
- Conexión a Internet.
- API Keys de los siguientes servicios usados sin costo:
  - Groq.
  - Google Gemini. (opcional)
  - Google Safe Browsing. 

## 1. Descargar el proyecto

Clonar el repositorio desde GitHub:

```bash
git clone URL_DEL_REPOSITORIO
```

Ingresar a la carpeta del proyecto:

```bash
cd Phishing-Detector-AI
```

## 2. Crear un entorno virtual

Crear un entorno virtual para instalar las dependencias del proyecto de manera aislada:

```bash
python -m venv venv
```

Activar el entorno virtual:

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

## 3. Instalar las dependencias

Instalar todas las librerías necesarias mediante el archivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

## 4. Configurar las API Keys

En la raíz del proyecto se encuentra el archivo `.env.example`, que contiene las variables de entorno necesarias para utilizar los servicios externos.

Crear una copia del archivo y nombrarla `.env`.

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env
```

**Linux / macOS:**

```bash
cp .env.example .env
```

Abrir el archivo `.env` y reemplazar los valores de ejemplo por las API Keys correspondientes:

```env
SAFE_BROWSING_API_KEY=TU_API_KEY
GROQ_API_KEY=TU_API_KEY
GROQ_MODEL=openai/gpt-oss-20b
GEMINI_API_KEY=TU_API_KEY
GEMINI_MODEL=TU_MODELO
```

Guardar los cambios antes de continuar.

**Nota:** Las API Keys son necesarias para realizar las consultas a los servicios externos. No se deben compartir ni subir al repositorio.

## 5. Ejecutar el servidor backend

El proyecto utiliza FastAPI para gestionar las solicitudes y coordinar el análisis de las URL.

Desde la raíz del proyecto, ejecutar:

```bash
python -m uvicorn backend.main:app --reload
```

Una vez iniciado, el servidor estará disponible en:

```text
http://127.0.0.1:8000
```

También es posible consultar la documentación interactiva de los endpoints de FastAPI en:

```text
http://127.0.0.1:8000/docs
```

**Importante:** Mantener esta terminal abierta mientras se utiliza la aplicación.

## 6. Ejecutar la interfaz gráfica

Abrir una segunda terminal, ingresar nuevamente a la carpeta del proyecto y activar el entorno virtual.

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

Ejecutar Streamlit:

```bash
streamlit run frontend/app.py
```

La aplicación abrirá automáticamente la interfaz gráfica en el navegador. En caso contrario, ingresar a:

```text
http://localhost:8501
```

## 7. Utilizar la aplicación

Una vez iniciados el backend y la interfaz gráfica:

1. Ingresar una URL en el campo de análisis.
2. Ejecutar el análisis mediante el botón correspondiente.
3. Esperar a que se realicen las validaciones y consultas a los servicios externos.
4. Consultar el resultado del análisis heurístico y de Google Safe Browsing.
5. Revisar la interpretación y las recomendaciones generadas mediante los modelos LLM.

## 8. URL de prueba

Para comprobar el funcionamiento de Google Safe Browsing, se puede utilizar la siguiente URL oficial de pruebas:

```text
https://testsafebrowsing.appspot.com/s/phishing.html
```

Esta dirección permite probar la detección de una URL clasificada como phishing sin utilizar un sitio malicioso real.

## 9. Detener la aplicación

Para detener los servicios, regresar a cada terminal y presionar:

```text
CTRL + C
```

Se recomienda detener primero Streamlit y posteriormente el servidor de FastAPI.

## Consideraciones

- Ambos servicios deben permanecer ejecutándose simultáneamente para utilizar la aplicación.
- Se requiere conexión a Internet para consultar las API externas.
- El funcionamiento de los proveedores LLM depende de la disponibilidad de sus servicios y de las API Keys configuradas.
- Los resultados son orientativos y no garantizan la detección de todas las amenazas.
- No se recomienda ingresar credenciales ni información personal en sitios sospechosos durante las pruebas.

---
Desarrollado como utilería de consumo de API de modelos de lenguaje (LLM), integrada en una aplicación de análisis de URL potencialmente maliciosas.