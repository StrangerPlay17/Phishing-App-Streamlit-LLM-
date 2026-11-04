# Frontend Server
# -------------------------------------------
# LIBRARIES 

# Importa "Path" para trabajar con rutas de archivos y directorios
from pathlib import Path

# Importa "requests" para realizar solicitudes HTTP al backend
import requests

# Importa "streamlit" para construir la interfaz web de la aplicación
import streamlit as st

# ------------------------------------------
# CONFIGURACION INICIAL 

# Define la ruta del endpoint encargado de analizar las URLs
API_URL = "http://127.0.0.1:8000/analyze"

# Obtiene la ruta absoluta de la carpeta frontend
FRONTEND_DIR = Path(__file__).resolve().parent

# Construye la ruta del archivo CSS utilizado para personalizar la interfaz
STYLES_PATH = FRONTEND_DIR / "styles.css"

# Configura los metadatos iniciales de la app
st.set_page_config(
    page_title="Phishing Detector AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)
# ------------------------------------------
# CARGA DEL ARCHIVO CSS DE LA APP


# Define una función para cargar los estilos CSS desde un archivo externo
def load_css(path: Path) -> None:
    try:
        # Lee y asigna el contenido del archivo CSS a una variable usando codificación UTF-8
        css = path.read_text(encoding="utf-8")

        # Inserta el CSS dentro de la interfaz mediante una etiqueta HTML segura
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    # Si no se encuentra el archivo CSS, se muestra una advertencia
    except FileNotFoundError:

        st.warning(
            "No se encontró el archivo styles.css "
            "La aplicación usará los estilos predeterminados"
        )
# ----------------------------------------
# APP

# Ejecuta la función para aplicar el CSS en styles.css
load_css(STYLES_PATH)

# -----------------------------------------
# HEADER


# Inserta el encabezado principal usandon componentes HTML usando "markdwn" para texto y contenido
st.markdown(
    """
    <div class="hero">
        <div class="hero-icon">🛡️</div>
        <div class="hero-copy">
            <div class="eyebrow">AI-POWERED SECURITY ANALYSIS</div>
            <h1>Phishing Detector <span>AI</span></h1>
            <p>Detecta señales de phishing mediante análisis heurístico,
            inteligencia artificial y Google Safe Browsing.</p>
        </div>
        <div class="hero-status"><span></span> PROTECTION ANALYSIS</div>
    </div>
    """,
    unsafe_allow_html=True, # Permite la ejecucion del header 
)
# -----------------------------------------
# ENTRADA DE URL

# Muestra el título y la descripción de la sección de análisis
st.markdown(
    """
    <div class="section-heading">
        <div>
            <div class="eyebrow">START SCANNING</div>
            <h2>Analiza una URL</h2>
        </div>
        <p>Introduce el enlace completo que deseas revisar.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# Agrupa el campo de entrada y el botón dentro de un contenedor visual
with st.container(border=True):

    # Crea un campo de texto para recibir la URL que se desea analizar
    url = st.text_input(
        "URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
        help="Incluye el protocolo, por ejemplo https://",
    )

    # Crea el botón que inicia el proceso de análisis
    analyze_button = st.button(
        "⌕  Analizar URL",
        type="primary",
        use_container_width=True,
    )


# Muestra un mensaje al usuario ebajo del boton 
st.markdown(
    '<p class="disclaimer">⚠️ No abras enlaces sospechosos para comprobar su veracidad '
    '.</p>',
    unsafe_allow_html=True,
)
# -----------------------------------------
# SECCIÓN AL PRESIONARSE EL BOTON DE ANALISIS  

# Comprueba si el usuario ha presionado el botón de análisis
if analyze_button:

    # Verifica que el campo de entrada no esté vacío
    if not url.strip():
        # Si esta vacio, lanza una mensaje de error 
        st.warning("Por favor, introduce una URL.")

    else:

        # Muestra un indicador de carga al usuario mientras se procesa la solicitud
        with st.spinner("Analizando URL... Esto puede tardar unos segundos."):

            # Bloque try para manejar posibles errores durante la solicitud
            try:

                # Envía la URL al endpoint del backend mediante una solicitud POST
                # en formato JSON
                response = requests.post(
                    API_URL, # Ruta endpoint en backend 
                    json={"url": url.strip()}, # Elimina los espacios en blanco de la url
                    timeout=(5, 120), # Establece un tiempo de espera de 5 seg de conexion y 2 min de recepcion del recurso solicitado
                )

                # Comprueba si la respuesta contiene un código HTTP de error
                response.raise_for_status()

                # Convierte la respuesta JSON del backend en un diccionario de Python
                result = response.json()

                # -------------------------------------------------------------------
                # EXTRACCIÓN DE DATOS DEL BACKEND 
            

                # Extrae los resultados devueltos por el backend desde services.py
                # y asigna valores predeterminados cuando un campo no está disponible
                risk = result.get("risk_level", "Desconocido")
                score = max(0, min(100, int(result.get("risk_score", 0))))
                heuristics = result.get("heuristics") or {}
                safe_browsing = result.get("safe_browsing") or {}
                llm_result = result.get("llm") or {}

                # --------------------------------------------------------------------
                # SECCION DE CLASIFICACIÓN DEL NIVEL DE RIESGO

                # Asigna una clase CSS, un icono y un mensaje según el nivel de riesgo
                if risk == "Alto": # Riesgo alto en la respuesta 
                    risk_class, risk_icon, risk_message = (
                        "risk-high",
                        "🚨",
                        "Se detectaron señales importantes de riesgo."
                    )
                elif risk == "Medio": # Riesgo medio en la respuesta 
                    risk_class, risk_icon, risk_message = (
                        "risk-medium",
                        "⚠️",
                        "La URL presenta señales que requieren revisión."
                    )
                else:  # Riesgo bajo en la respuesta
                    risk_class, risk_icon, risk_message = (
                        "risk-low",
                        "✓",
                        "No se identificó un nivel elevado de riesgo."
                    )


                # Inserta el encabezado de la sección donde se presentarán los resultados del backend 
                st.markdown(
                    '<div class="results-anchor"></div>',
                    unsafe_allow_html=True
                )

                st.markdown(
                    """
                    <div class="section-heading results-heading">
                        <div>
                            <div class="eyebrow">SCAN REPORT</div>
                            <h2>Resultados del análisis</h2>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Muestra el nivel de riesgo y la puntuación obtenida en la interfaz 
                st.markdown(
                    f"""
                    <div class="risk-panel {risk_class}">
                        <div class="risk-panel-top">
                            <div>
                                <div class="eyebrow">RISK LEVEL</div>
                                <div class="risk-title">{risk_icon} {risk}</div>
                                <p>{risk_message}</p>
                            </div>
                            <div class="score-circle">
                                <strong>{score}</strong>
                                <span>/ 100</span>
                            </div>
                        </div>
                        <div class="score-labels">
                            <span>0 · Bajo</span>
                            <span>100 · Alto</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Muestra el nivel de riesgo mediante una barra de progreso en la interfaz
                st.progress(score / 100)

                # --------------------------------------------------------------------
                # SECCIÓN DE PUNTUACIÓN

                # Muestra las puntuaciones obtenidas durante el análisis
                st.markdown("#### 📊 Desglose de puntuación")

                # Divide el espacio de la interfaz en dos columnas
                col1, col2 = st.columns(2)

                # Muestra en la primer columna la puntuación generada en el análisis heurístico
                with col1:

                    st.metric(
                        "Heuristic Score",
                        f"{heuristics.get('score', 0)}/100"
                    )

                # Muestra en la segunda columna la puntuación final calculada por el backend
                with col2:

                    st.metric(
                        "Final Risk Score",
                        f"{score}/100"
                    )


                # --------------------------------------------------------------------
                # SECCIÓN DE VERIFICACIÓN DE SAFE BROWSING

                # Obtiene el estado de la verificación realizada por Safe Browsing
                threat_detected = safe_browsing.get("is_threat")

                # Si se detecta una amenaza, se muestra una alerta de riesgo
                if threat_detected is True:

                    st.error(
                        "Google Safe Browsing detectó una potencial amenaza "
                       
                    )

                # Si no se detectan amenazas, se muestra una confirmación
                elif threat_detected is False:

                    st.success(
                        "Google Safe Browsing no encontró coincidencias de amenazas conocidas"
                    )

                # Si no se pudo realizar la consulta, se muestra una advertencia
                else:

                    st.warning(
                        "Google Safe Browsing no pudo completar la verificación y "
                        "la puntuación se basa en el análisis heurístico"
                    )

                # Mensaje de nota o texto secundario al usuario 
                st.caption(
                    "La puntuación es un indicador determinista de riesgo, "
                    "no una probabilidad estadística."
                )

                # ------------------------------------------------------------------
                # SECCIÓN DE ANÁLISIS DE AI

                # Muestra la seccion correspondiente al analisis generado por IA
                st.markdown("---")
                st.markdown("#### 🤖 Análisis de inteligencia artificial")

                # Obtiene el proveedor de IA que genero el analisis
                provider = llm_result.get("provider", "Desconocido")

                # Si el análisis fue realizado mediante Groq
                if provider == "Groq":
                    # Se muestra un mensaje al usuario indicando que se uso Groq
                    st.success("Proveedor LLM: Groq")

                # Sino, al usarse Gemini como AI
                elif provider == "Gemini":
                     # Muestra un mensaje al usuario indicand que se uso Gemini 
                    st.info("Proveedor LLM: Gemini")

                # Si no se tiene un proveedor, se muestra una advertencia
                else:

                    st.warning("No se identificó un proveedor de IA disponible")

                # Muestra el resumen al usuario generado por el modelo de IA 
                st.write(
                    llm_result.get( # Resultado del resumen de IA por el backend 
                        "summary",
                        "No hay resumen disponible."
                    )
                )

                # Si se tiene un error en el resultado, se muestra la información 
                if llm_result.get("error"):
                    with st.expander("Información del error del proveedor LLM"):
                        st.code(str(llm_result["error"]))


                # ---------------------------------------------------------------
                # SECCIÓN DE RECOMENDACIONES

                # Muestra la sección de recomendaciones en la interfaz
                st.markdown("#### 💡 Recomendaciones")
                # Obtiene la lista de recomendaciones generadas por el modelo
                recommendations = llm_result.get("recommendations") or []

                # Recorre y muestra las recomendaciones generadas por el modelo
                if recommendations:

                    for recommendation in recommendations:

                        st.markdown(f"- {recommendation}")

                else: # Sino hay recomendaciones

                    st.info("No hay recomendaciones disponibles.")


                # ------------------------------------------------------------------
                # SECCIÓN DE INDICADORES HEURÍSTICOS


                # Muestra la sección en la interfaz 
                st.markdown("---")
                st.markdown("#### 🔎 Indicadores detectados")

                # Obtiene los indicadores del analisis heuristico
                indicators = heuristics.get("indicators") or []

                # Recorre y muestra los indicadores encontrados en el analisis heuristico
                if indicators:

                    for indicator in indicators:
                         # Muestra un mensaje con cada indicador encontrado 
                        st.warning(indicator)

                else: # Sino hay indicadores heuristicos 

                    st.success("No se detectaron indicadores heurísticos en esta URL.")


                # -----------------------------------------------------------------
                # SECCIÓN DE GOOGLE SAFE BROWSING
 
                # Muestra la division de la seccion en la interfaz
                st.markdown("---")
                st.markdown("#### 🌐 Google Safe Browsing")

                # Comprueba si el servicio de Safe Browsing estuvo disponible
                if not safe_browsing.get("available", False):
                    st.warning("No fue posible consultar Google Safe Browsing")

                    # Si hubo un error con Safe Browsing desde el backend 
                    if safe_browsing.get("error"):
                        # Muestra un mensaje de error si la consulta no pudo completarse
                        st.caption(str(safe_browsing["error"]))

                # Si hubo amenazas, muestra los detalles de aquellas identificadas por Safe Browsing
                elif safe_browsing.get("is_threat"):

                    st.error("Google Safe Browsing encontró una amenaza conocida.")

                    # Recorre las coincidencias para mostrar el tipo de amenaza y plataforma
                    for match in safe_browsing.get("matches") or []:
                         # Muestra las amenazas y su plataforma en la interfaz 
                        st.markdown(
                            f"- **Threat type:** {match.get('threat_type', 'N/D')}  \n"
                            f"  **Platform:** {match.get('platform', 'N/D')}"
                        )

                # Si no se encontraron amenazas
                else:
                    # Se muestra un mensaje indicativo al usuario 
                    st.success("No se encontraron coincidencias en Google Safe Browsing")
                    st.caption("Sin embargo, no garantiza que la URL sea segura")


            # -------------------------------------------------------------
            # SECCIÓN DE MANEJO DE ERRORES
   

            # Captura errores cuando no es posible establecer conexión con el backend
            except requests.exceptions.ConnectionError:
                # Muestra un mensaje de error de conexion al usuario 
                st.error(
                    "No se pudo conectar con el backend. "
                    "Verifica que el servidor esté ejecutándose"
                )

            # Captura errores de respuestas HTTP del servidor 
            except requests.exceptions.HTTPError as error:

                try:

                    # Obtiene el mensaje de error devuelto por el backend
                    message = response.json().get("detail", str(error))

                # Si la respuesta no contiene un JSON válido, utiliza el error original
                except (ValueError, AttributeError):
                    # Convierte el error en un string para su visualizacion
                    message = str(error)
                # Muestra el error 
                st.error(f"Error del servidor: {message}")

            # Captura el caso en que la solicitud supera el tiempo máximo de espera de 2 min
            except requests.exceptions.Timeout:

                st.error("El análisis tardó demasiado. Inténtalo nuevamente.")

            # Captura errores al procesar o interpretar los datos recibidos del backend
            except (ValueError, TypeError, KeyError) as error:

                st.error(
                    f"La respuesta del backend no tiene el formato esperado: {error}"
                )

            # Captura cualquier otra excepción no contemplada anteriormente
            except Exception as error:

                st.error(f"Ocurrió un error inesperado: {error}")


