# Backend Sever
# ---------------------------------------------------------------
# LIBRARIES 

# Importa "FastAPI" para crear una API REST y "HTTPException" para devolver errores HTTP
from fastapi import FastAPI, HTTPException

# Importa "BaseModel" para definir modelos de datos y validar 
# de forma automatica la información que recibe la API
from pydantic import BaseModel

# Importa la función análisis de phishing definida en services.py
from services import analyze_phishing
#------------------------------------------------------------------
# APP

# Crea una instancia de la app FastAPI con sus metadatos 
app = FastAPI(
    title="Phishing Detector AI",
    description="API para detectar URLs potencialmente maliciosas.",
    version="1.0.0"  
)


# Define un modelo de datos llamado "URLRequest" donde establece qué información debe recibir la API
class URLRequest(BaseModel):
    # Define un campo obligatorio 'url' que debe ser de tipo string 
    url: str


# Crea un Endpoint tipo GET de la ruta raiz "/" de la API
@app.get("/")
def home():
    # Devuelve un objeto JSON indicando que la API esta en funcionamiento 
    return {
        "message": "Phishing Detector AI API is running"
    }

# Crea Endpoint tipo POST de la ruta "/analyze" la cual el usuario envia con la URL a analizar
@app.post("/analyze")
def analyze(request: URLRequest): # Recibe una URL como entrada

    # Try para atrapar errores en ejecucion 
    try:

        # Se extrae ".url" con la URL del texto recibido 
        # y se envia a la función analyze_phishing() para su analisis 
        # almacenando el resultado en "result"
        result = analyze_phishing(request.url)

        # Al no haber error, devuelve el resultado del análisis al cliente en un JSON
        return result


    # Si el formato URL fue invalido o no pudo ser procesado devuelve un ValueError 
    except ValueError as error:

        # Devuelve el error HTTP 400 (Bad Request)
        # str(error) y convierte el mensaje de error en texto
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )
    
    # Captura cualquier otra excepción no contemplada a un ValueError
    except Exception:
        # Devuelve un error HTTP 500 (Internal Server Error) con un mensaje de error
        raise HTTPException(
            status_code=500,
            detail="Ocurrió un error interno durante el análisis"
        )
