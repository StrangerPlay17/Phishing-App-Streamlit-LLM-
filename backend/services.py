# Servicios y logica del backend
# ------------------------------------------
# LIBRERÍAS

import os
import json

# Importa "ipaddress" para validar y reconocer direcciones IP
import ipaddress

# Importa "urlparse" para analizar y separar los componentes de una URL
from urllib.parse import urlparse

# Importa "requests" para realizar solicitudes HTTP a servicios externos
import requests

# Importa "load_dotenv" para cargar las variables definidas en el archivo .env
from dotenv import load_dotenv

# Importa el SDK de Google GenAI para utilizar modelos de Gemini
from google import genai

# Importa el cliente de Groq para realizar solicitudes a sus modelos de IA
from groq import Groq


# ------------------------------------------
# CONFIGURACIÓN VARIABLES DE ENTORNO


# Carga las variables de entorno definidas en el archivo .env
load_dotenv()

# ------------------------------------------
# CONFIGURACIÓN DE API KEYS Y MODELOS

# Obtiene la clave de acceso a la API de Google Safe Browsing
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

# Obtiene la clave de acceso y el modelo configurado para Groq (LLM)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv(
    "GROQ_MODEL",
    "llama-3.3-70b-versatile"
)

# Obtiene la clave de acceso y el modelo configurado para Gemini (LLM)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL")


# ------------------------------------------
# INICIALIZACIÓN DE CLIENTES LLM

# Crea una instancia del cliente Groq si se encuentra configurada su API key
# En caso contrario, asigna None para indicar que no está disponible
groq_client = (
    Groq(api_key=GROQ_API_KEY)
    if GROQ_API_KEY
    else None
)

# Crea una instancia del cliente Gemini si se encuentra configurada su API key
# En caso contrario, asigna None para indicar que no está disponible
gemini_client = (
    genai.Client(api_key=GEMINI_API_KEY)
    if GEMINI_API_KEY
    else None
)

# ------------------------------------------
# VALIDACIÓN DE URL

# Funcion que valida que la entrada contenga una URL HTTP/HTTPS válida
def validate_url(url: str): # Recibe un URL tipo string
   
    # Elimina los espacios al inicio y al final de la URL
    url = url.strip()

    # Analiza la URL y la divide en un objeto guardando su protocolo usado http, https 
    # dominio del servidor, ruta interna del sitio, y parametros de busqueda como:
    # .scheme (protocolo http/s)
    # .hostname (dominio o dirección del servidor en minúsculas)
    # .port (puerto de conexión, ej: 8501, 8080; si no, da None)
    # .username (usuario de autenticación integrado en la URL, usado a veces en engaños/phishing)
    # .password (contraseña de autenticación integrada en la URL)

    parsed = urlparse(url)

    # Verifica que el protocolo utilizado sea HTTP o HTTPS 
    if parsed.scheme not in ("http", "https"): 

        raise ValueError( # Si no contiene ningun protocolo http/s levanta un error 
            "La URL debe comenzar con http:// o https://"
        )

    # Comprueba que la URL contenga un nombre de dominio o dirección IP
    if not parsed.hostname:
        # Sino, levanta un error de dominio no valido 
        raise ValueError("La URL no contiene un dominio válido.")

    # Evita que la URL contenga credenciales de usuario o contraseña
    if parsed.username or parsed.password:
         # Levanta un error si se encuentran credenciales en la URL 
        raise ValueError(
            "No se permiten credenciales dentro de la URL."
        )

    # Comprueba que el puerto especificado tenga un formato válido
    try:

        parsed.port

    except ValueError:
         # Si el puerto de la URL no es valido, levanta un Valuerror 
        raise ValueError("El puerto de la URL no es válido.")

    # Devuelve la URL al no haber errores 
    return url


# ------------------------------------------
# ANÁLISIS HEURÍSTICO

# Funcion que identifica características que podrían indicar phishing
def analyze_url_heuristics(url: str):  # Recibe un URL tipo string 
    

    # Separa los componentes de la URL y obtiene el dominio
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    # Inicializa la lista de indicadores y la puntuación de riesgo
    indicators = []
    score = 0

    # --------------------------------------
    # USO DE HTTP EN LUGAR DE HTTPS


    # Comprueba si la URL usa HTTP, la cual no cifra la comunicacion mediante TLS
    if parsed.scheme == "http":

        indicators.append(  # Si usa http, se agrega un indicador de HTTP que es inseguro
            "La URL utiliza HTTP en lugar de HTTPS."
        )

        # Incrementa la puntuación por utilizar una conexión sin HTTPS
        score += 10

    # --------------------------------------
    # DIRECCIÓN IP COMO DOMINIO


    # Comprueba si el dominio corresponde directamente a una dirección IP
    try:

        # Valida si el dominio es una direccion IP con ipaddress
        ipaddress.ip_address(domain)

        indicators.append( # Si es, se agrega a los indicadores 
            "El dominio utiliza una dirección IP directamente."
        )

        # Incrementa la puntuación cuando se utiliza una IP en lugar de un dominio
        score += 20

    # Si el dominio no tiene un formato de dirección IP, continúa con el análisis
    except ValueError:

        pass

    # --------------------------------------
    # LONGITUD DEL DOMINIO

    # Identifica dominios que superan los 40 caracteres
    if len(domain) > 40:

        indicators.append("El dominio tiene una longitud inusual.")

        # Incrementa la puntuación por la longitud excesiva del dominio
        score += 10

    # --------------------------------------
    # CANTIDAD DE SUBDOMINIOS

    # Comprueba si el dominio contiene cuatro o más puntos
    if domain.count(".") >= 4:
        # Al contener 4 o mas, se agrega a la lista de indicadores
        indicators.append(
            "El dominio contiene varios subdominios."
        )

        # Incrementa la puntuación por la cantidad de subdominios
        score += 10

    # --------------------------------------
    # CARACTERES SOSPECHOSOS

    # Comprueba si la URL contiene el carácter @, que puede utilizarse para ocultar el destino
    if "@" in url:

        indicators.append("La URL contiene el carácter @.")

        # Incrementa la puntuación por la presencia del carácter
        score += 15

    # --------------------------------------
    # PALABRAS SOSPECHOSAS

    # Define palabras que pueden aparecer frecuentemente en enlaces de phishing
    suspicious_words = [

    "identity-verification", "login-portal", "signin-hub", "credential-verification",
    "password-recovery", "reset-auth", "validate-account", "security-authentication",
    "webmail-access", "sso-login", "single-signon", "employee-portal", "hr-access",
    "security-alert", "account-suspended", "account-blocked", "unauthorized-access",
    "action-required", "immediate-action", "expired-notice", "suspicious-activity",
    "re-verify", "system-update", "critical-update", "safety-alert",
    "billing-update", "invoice-payment", "payment-failed", "refund-request",
    "money-transfer", "crypto-wallet", "dispute-center", "claim-reward",
    "credit-card-update", "overdue-bill", "cancel-subscription",
]

    # Convierte la URL a minúsculas para realizar una comparación sin distinguir mayúsculas
    url_lower = url.lower()

    # Obtiene palabras sospechosas que aparecen dentro de la URL 
    found_words = [
        word for word in suspicious_words
        if word in url_lower
    ]

    # Comprueba si se encontró alguna de las palabras definidas
    if found_words:

        indicators.append(
            "Contiene palabras frecuentemente asociadas con "
            "páginas de autenticación o verificación: "
            + ", ".join(found_words)
        )

        # Incrementa 5 puntos por cada palabra encontrada, con un máximo de 20
        score += min(len(found_words) * 5, 20)

    # --------------------------------------
    # CANTIDAD DE GUIONES

    # Comprueba si el dominio contiene tres o más guiones
    if domain.count("-") >= 3:

        indicators.append(
            "El dominio contiene varios guiones."
        )

        # Incrementa la puntuación por la presencia de varios guiones
        score += 10

    # --------------------------------------
    # SERVICIOS DE ACORTAMIENTO

    # Define una lista de dominios pertenecientes a servicios de acortamiento de URLs
    shorteners = [
       "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
        "rb.gy", "short.io", "rebrand.ly", "tiny.cc", "bl.ink",
        "lnkd.in", "youtu.be", "fb.me", "wa.me", "t.me", "goo.gl"
    ]

    # Comprueba si el dominio corresponde a alguno de los servicios identificados
    if domain.lower() in shorteners:

        indicators.append(
            "La URL utiliza un servicio de acortamiento."
        )

        # Incrementa la puntuación por utilizar un enlace acortado
        score += 15

    # Al finalizar devuelve la puntuación limitada a 100 y la lista de indicadores detectados
    return {
        "score": min(score, 100),
        "indicators": indicators
    }


# ------------------------------------------
# GOOGLE SAFE BROWSING COMO EXTERNAL SERVICE 

# Funcion que consulta si Google Safe Browsing identifica una URL como amenaza
def check_safe_browsing(url: str): # Recibe una URL tipo string 

    # Comprueba si se encuentra configurada la clave de acceso a su API
    if not SAFE_BROWSING_API_KEY:

        # Devuelve un resultado indicando que el servicio no está disponible
        return {
            "available": False,
            "is_threat": None,
            "matches": [],
            "error": "Safe Browsing API key no configurada"
        }

    # Define el endpoint de Google Safe Browsing para consultar amenazas conocidas
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        "threatMatches:find"
    )

    # Define los parámetros de la solicitud y la clave de acceso
    params = {
        "key": SAFE_BROWSING_API_KEY
    }

    # Construye el cuerpo de la solicitud JSON con los tipos de amenazas y la URL que se desea verificar
    payload = {
        "client": {
            "clientId": "phishing-detector-ai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    # Prueba ejecutar la solicitud y procesa la respuesta del servicio
    try:

        # Envía los parámetros y el cuerpo JSON mediante POST al endpoint de Safe Browsing
        response = requests.post(
            endpoint,
            params=params,
            json=payload,
            timeout=10
        )

        # Comprueba que la respuesta HTTP recibida no contenga errores
        response.raise_for_status()

        # Convierte la respuesta JSON en un diccionario de Python
        data = response.json()

        # Obtiene las coincidencias de amenazas encontradas
        matches = data.get("matches", [])

        # Al final dvuelve el estado de la consulta y los detalles de las amenazas detectadas
        return {
            "available": True,
            "is_threat": len(matches) > 0,
            "matches": [
                {
                    "threat_type": item.get(
                        "threatType", "UNKNOWN"
                    ),
                    "platform": item.get(
                        "platformType", "UNKNOWN"
                    )
                }
                for item in matches
            ],
            "error": None
        }

    # En caso de errores relacionados con la solicitud HTTP o la conexión al servicio
    except requests.RequestException as error:

        # Se captura y devuelve el estado de la consulta con un mensaje del error
        return {
            "available": False,
            "is_threat": None,
            "matches": [],
            "error": str(error)
        }


# ------------------------------------------
# PROTECCIÓN DE URL

# Funcion que elimina parámetros y fragmentos de la URL antes de enviarla al LLM
def redact_url(url: str): # Recibe una URL como tipo string 

    # Separa los componentes de la URL
    parsed = urlparse(url)

    # Sustituye los parámetros de consulta y el fragmento por cadenas vacias
    # para evitar enviar información que no sea necesaria en el analisis
    return parsed._replace(
        query="",
        fragment=""
    ).geturl() # Devuelve la nueva URL limpiada 


# ------------------------------------------
# CONSTRUCCIÓN DEL PROMPT COMPARTIDO

# Funcion que construye las instrucciones que recibirán ambos modelos LLM
def build_analysis_prompt(url, heuristics, safe_browsing):

    # Elimina los parámetros y fragmentos de la URL antes de incluirla en el prompt
    safe_url = redact_url(url) # Funcion de limpieza de URL creada 

    # Construye el prompt con la URL, los resultados heuristicos y la respuesta de Safe Browsing
    # con e mismo formato para ambos modelos LLM

    # En el prompt se inserta la URL, las heuristicas del analisis y el analisis de Google Safe Browsing
    # mediante: {json.dumps(heuristics, ensure_ascii=False)} 

    # Regresa el prompt 
    return f"""  
You are a cybersecurity assistant specialized in phishing detection.

Analyze the following URL using ONLY the provided information

URL:
{safe_url}

Heuristic analysis:
{json.dumps(heuristics, ensure_ascii=False)} 

Google Safe Browsing:
{json.dumps(safe_browsing, ensure_ascii=False)} 

Instructions:
- Explain potential security risks.
- Do not claim a website is malicious without evidence.
- A Safe Browsing match is evidence of a known threat.
- An empty Safe Browsing result does NOT guarantee safety.
- Treat heuristic indicators as warning signs, not proof.
- Do not invent information.
- Respond in Spanish.
- Give at least 5 recommendations a bit technical.

Return ONLY a valid JSON:

{{
    "summary": "Brief explanation",
    "recommendations": [
        "Recommendation 1",
        "Recommendation 2"
    ]
}} 
"""


# ------------------------------------------
# PROOVEDOR PRINCIPAL LLM GROQ

# Funcion que realiza el analisis usando el modelo configurado en Groq
def analyze_with_groq(prompt): # Recibe el prompt como parametro 

    # Comprueba que el cliente de Groq se encuentre inicializado
    if not groq_client:
        # En caso que no este inicializado, se da un Runtimeerror
        raise RuntimeError("Groq no está configurado.")

    # Envia el prompt realizado al modelo mediante el endpoint de chat completions
    response = groq_client.chat.completions.create(
        model=GROQ_MODEL, # Modelo openai/gpt-oss-20b usado desde el .env
        messages=[
            {
                "role": "system",
                "content": (
                    "Eres un experto en ciberseguridad "
                    "Responde exclusivamente con JSON válido"
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],

        # Solicita al modelo que devuelva la respuesta en formato JSON
        response_format={"type": "json_object"},

        # Define una temperatura baja para obtener respuestas más consistentes
        temperature=0.2,

        # Establece el tiempo máximo de espera de la solicitud
        timeout=25
    )

    # Convierte el contenido JSON generado por el modelo en un diccionario de Python
    result = json.loads(
        response.choices[0].message.content
    )

    # Devuelve el analisis junto con el nombre del proveedor "Groq" usado
    return {
        **result,
        "provider": "Groq"
    }


# ------------------------------------------
# PROVEEDOR SECUNDARIO LLM GEMINI

# Funcion que realiza el analisis de pishing usando el modelo configurado en Gemini
def analyze_with_gemini(prompt):

    # Comprueba que el cliente y el modelo de Gemini estén configurados
    if not gemini_client or not GEMINI_MODEL:
        # Al no estar configurados, se da un runtimerrror
        raise RuntimeError("Gemini no está configurado")

    # Al estar presentes, se envia el prompt al modelo mediante el método generate_content
    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL, # Modelo en Gemini gemini-3.8-flash
        contents=prompt,
        config={

            # Solicita que la respuesta generada tenga formato JSON
            "response_mime_type": "application/json"
        }
    )

    # Convierte el contenido JSON generado por el modelo en un diccionario de Python
    result = json.loads(response.text)

    # Devuelve el analisis del modelo junto con el nombre del proveedor Gemini 
    return {
        **result,
        "provider": "Gemini"
    }


# ------------------------------------------
# SELECCIÓN DE PROVEDOOR LLM 

# Funcion que selecciona al proveedor LLM disponible 
# donde prueba usar Groq como principal y recurrir a Gemini si no esta disponible 
def analyze_with_llm(url, heuristics, safe_browsing):
  
    # Construye el prompt con los resultados obtenidos durante el analisis de la URL
    prompt = build_analysis_prompt(  # Funcion declarada previamente que regresa el prompt
        url,
        heuristics,
        safe_browsing
    )

    # Inicializa una lista para almacenar los errores de cada proveedor
    errors = []

    # --------------------------------------
    # ANALISIS MEDIANTE LLM GROQ

    try:

        # Muestra en consola que se iniciara el analisis con Groq
        print("Intentando análisis con Groq...")

        # Ejecuta el análisis usando el proveedor LLM Groq
        result = analyze_with_groq(prompt)

        # Muestra en consola que el analisis con Groq se completo 
        print("Análisis completado con Groq")

        # Devuelve el resultado sin necesidad de usar otro provedor
        return result

    # Captura cualquier error durante el analisis con Groq
    except Exception as error:

        # Se almacena el mensaje de error para incluirlo en el resultado final 
        errors.append(f"Groq: {str(error)}")

        # Muestra el error por consola si falla 
        print(f"Groq falló: {error}")

    # --------------------------------------
    # ANALISIS MEDIANTE GEMINI

    # En caso de no haber estado disponible Groq o un error
    # esta seccion de codigo se ejecuta 
    try:

        # Indica en la consola que se iniciara el analisis con Gemini
        print("Intentando análisis con Gemini...")

        # Ejecuta el análisis usando el proveedor de Gemini 
        result = analyze_with_gemini(prompt)

        # Indica que el analisis con Gemini se completo 
        print("Análisis completado con Gemini")

        # Al final devuelve el resultado obtenido
        return result

    # Captura cualquier error sucedido durante el analisis con Gemini
    except Exception as error:

        # Almacena el mensaje de error 
        errors.append(f"Gemini: {str(error)}")

        # Muestra el error por consola 
        print(f"Gemini falló: {error}")

    # --------------------------------------
    # RESPUESTA ALTERNATIVA SI AMBOS MODELOS FALLAN
  
    # Devuelve un resultado predeterminado cuando ninguno de los proveedores esta disponible
    return {
        "summary": (
            "No fue posible completar el análisis "
            "con los modelos de inteligencia artificial."
        ),
        "recommendations": [
            "Consulta los resultados de Google Safe Browsing.",
            "Revisa los indicadores heurísticos.",
            "Evita introducir información personal en sitios sospechosos."
        ],
        "provider": "Fallback",

        # Junta los errores de ambos proveedores en un solo mensaje
        "error": " | ".join(errors)
    }


# ------------------------------------------
# ANALISIS PRINCIPAL DE PHISHING DE LA APP 

# Funcion principal llamada que inicia los diferentes metodos de deteccion de phishing al 
# usar el Endpoint con la ruta /analyze del backend 
def analyze_phishing(url: str):

    # Valida la URL antes de iniciar cualquier proceso de analisis
    url = validate_url(url) # Funcion de validacion de URL realizada  

    # Ejecuta el análisis heuristico para identificar caracteristicas sospechosas
    heuristics = analyze_url_heuristics(url) # Funcion de identificacion de phishing realizada

    # Consulta Google Safe Browsing para comprobar si existe una amenaza conocida
    safe_browsing = check_safe_browsing(url) # Funcion que usa la API de Safe Browsing 

    # Ejecuta el análisis mediante IA usando Groq o Gemini como alternativa
    llm_result = analyze_with_llm(
        url,
        heuristics,
        safe_browsing
    )

    # --------------------------------------
    # CALCULO FINAL DE PUNTUACION Y NIVEL DE RIESGO


    # Se obtiene la puntuacion inicial generada por el analisis heuristico
    # donde la puntuacion es determinista y no representa una probabilidad estadística en si
    score = heuristics["score"]

    # Si la API de Safe Browsing detecta una amenaza, establece una puntuación mínima de 90
    if safe_browsing["is_threat"] is True:

        score = max(score, 90)

    # Clasifica el nivel de riesgo segun la puntuación final obtenida
    if score >= 60:

        risk = "Alto"

    elif score >= 30:

        risk = "Medio"

    else:

        risk = "Bajo"

    # Asigna el nivel de riesgo como Alto si Safe Browsing confirma una amenaza
    if safe_browsing["is_threat"] is True:

        risk = "Alto"

    # --------------------------------------
    # RETORNO DEL RESULTADO OBTENIDO EN FORMATO JSON 

    # Devuelve los resultados de los diferentes metodos de analisis realizados
    return {
        "url": url,                        # URL consultada
        "risk_level": risk,                # Nivel de riesgo (alto,medio,bajo)
        "risk_score": score,               # Puntuacion de riesgo de 0 a 100
        "heuristics": heuristics,          # Indicadores de riesgo 
        "safe_browsing": safe_browsing,    # Amenazas detectadas en Safe Browsing
        "llm": llm_result                  # Respuesta del analisis realizado mediante Groq o Gemini 
    }