import streamlit as st
import requests
from urllib.parse import urlparse, parse_qs

st.title("Aplicación Streamlit")

# URL de la aplicación Flask (donde está corriendo el servidor Flask)
FLASK_APP_URL = "https://blank-app-xyew7evq8qsy8mbhswdtvq.streamlit.app/"

if "access_token" not in st.session_state:
    st.write("Para autorizar, haz clic en el siguiente enlace:")
    try:
        response = requests.get(FLASK_APP_URL)  # Obtiene el HTML desde Flask
        html_content = response.text
        st.components.v1.html(html_content, height=75)  # Muestra el enlace en Streamlit
    except requests.exceptions.RequestException as e:
        st.error(f"Error al obtener el enlace de autorización: {e}")
        st.stop() # Detiene la ejecución de Streamlit si no se puede obtener el enlace

    if st.experimental_get_query_params():
        query_params = st.experimental_get_query_params()
        if "code" in query_params:
            code = query_params["code"][0]
            try:
                token_response = requests.post(f"{FLASK_APP_URL}/token_exchange", data={"code": code})
                token_response.raise_for_status() # Lanza excepción para códigos de error HTTP
                token_data = token_response.json()
                if "access_token" in token_data:
                    st.session_state.access_token = token_data["access_token"]
                    st.session_state.refresh_token = token_data.get("refresh_token")
                    st.write("Autorización exitosa!")
                else:
                    st.error("Error al obtener el token.")
            except requests.exceptions.RequestException as e:
                st.error(f"Error al intercambiar el token: {e}")
            st.experimental_set_query_params({})  # Limpia los parámetros de la URL

elif "access_token" in st.session_state:
    st.write("Token de acceso:", st.session_state.access_token)
    try:
        headers = {"Authorization": f"Bearer {st.session_state.access_token}"}
        response = requests.get("https://api.kick.com/public/v1/categories?q=ga%", headers=headers)
        response.raise_for_status()
        data = response.json()
        st.write("Datos de la API:")
        st.write(data)
    except requests.exceptions.RequestException as e:
        st.error(f"Error al acceder a la API: {e}")
        if response and response.status_code == 401:  # Verifica si response existe y si es 401
            del st.session_state.access_token
            st.write("El token ha expirado. Por favor, vuelve a autorizar.")