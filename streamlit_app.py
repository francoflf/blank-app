import streamlit as st
import requests
from urllib.parse import urlparse, parse_qs

st.title("Aplicación Streamlit")

# URL de la aplicación Flask (donde está corriendo el servidor Flask)
FLASK_APP_URL = "https://blank-app-xyew7evq8qsy8mbhswdtvq.streamlit.app/"

if "access_token" not in st.session_state:  # Verifica si ya hay un token
    st.write("Para autorizar, haz clic en el siguiente enlace:")
    response = requests.get(f"{FLASK_APP_URL}/")  # Obtiene el enlace de autorización desde Flask
    html_content = response.text  # Extrae el HTML del enlace
    st.components.v1.html(html_content, height=75) # Muestra el enlace en Streamlit

    # Manejo de la redirección (Streamlit no maneja redirecciones directamente)
    if st.experimental_get_query_params():
        query_params = st.experimental_get_query_params()
        if "code" in query_params:
            code = query_params["code"][0]
            # Intercambiar el código por el token (usando Flask como intermediario)
            token_response = requests.post(f"{FLASK_APP_URL}/token_exchange", data={"code": code})
            token_data = token_response.json()
            if "access_token" in token_data:
                st.session_state.access_token = token_data["access_token"]
                st.session_state.refresh_token = token_data.get("refresh_token") #Puede que no esté
                st.write("Autorización exitosa!")
            else:
                st.error("Error al obtener el token.")
            st.experimental_set_query_params({}) # Limpia los parámetros de la URL

elif "access_token" in st.session_state:
    st.write("Token de acceso:", st.session_state.access_token)
    # Hacer solicitudes a la API usando st.session_state.access_token
    try:
        headers = {"Authorization": f"Bearer {st.session_state.access_token}"}
        response = requests.get("https://api.kick.com/public/v1/categories?q=ga%", headers=headers)
        response.raise_for_status() # Lanza excepción si el código de estado no es 2xx
        data = response.json()
        st.write("Datos de la API:")
        st.write(data) # Mostrar los datos en Streamlit
    except requests.exceptions.RequestException as e:
        st.error(f"Error al acceder a la API: {e}")
        if response.status_code == 401: # Si es error de autenticación
            del st.session_state.access_token # Borra el token y pide que se vuelva a autorizar
            st.write("El token ha expirado. Por favor, vuelve a autorizar.")


# Ruta adicional en Flask para el intercambio de tokens (necesario para Streamlit)
@app.route("/token_exchange", methods=["POST"])
def token_exchange():
    code = request.form.get("code")
    code_verifier = session.get("code_verifier")
    token_data = get_access_token(code, code_verifier)
    return token_data

if __name__ == "__main__":
    try:
        print("Aplicación Flask iniciada en hhttps://blank-app-xyew7evq8qsy8mbhswdtvq.streamlit.app/")
        app.run(debug=True, port=5001)
    except Exception as e:
        print(f"Error al iniciar Flask: {e}")
        import traceback
        traceback.print_exc()