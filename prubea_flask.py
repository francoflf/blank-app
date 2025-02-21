import requests
import secrets
import hashlib
import base64
from urllib.parse import urlencode, quote
from flask import Flask, request, redirect, url_for, session

# Datos de tu aplicación
CLIENT_ID = "01JMMS7DVKKB10JM3KHCMCQ355"
CLIENT_SECRET = "29ccdadaac0c46088f55f75edc11d7c559db8f0c5a8c1f2e79793f7e9f8d1848"
# REDIRECT_URI = "https://blank-app-7n69k0rfqzl.streamlit.app"
REDIRECT_URI = "http://127.0.0.1:5001/callback"

SCOPES = "user:read channel:read"

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)  # ¡Secreto para la sesión!




def generate_code_verifier():
    """Genera un código verificador aleatorio."""
    return secrets.token_urlsafe(32)

def generate_code_challenge(code_verifier):
    """Genera un código challenge usando PKCE."""
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('+', '-').replace('/', '_').replace('=', '')
    return code_challenge

# --- Flujo de autorización ---

def get_authorization_url():
    """Construye la URL de autorización."""
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(16)  # Genera un valor aleatorio para el estado

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state
    }

    authorization_url = f"https://id.kick.com/oauth/authorize?{urlencode(params)}"
    return authorization_url, code_verifier, state


def get_access_token(authorization_code, code_verifier):
    """Intercambia el código de autorización por un token de acceso."""
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        "code": authorization_code
    }       
        

    response = requests.post("https://id.kick.com/oauth/token", data=data)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error al obtener el token: {response.status_code} - {response.text}")
        return None



def refresh_access_token(authorization_code):
    """Refresca el token de acceso usando el refresh token."""
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": authorization_code,
    }
    response = requests.post("https://id.kick.com/oauth/token", data=data)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error al refrescar el token: {response.status_code} - {response.text}")
        return None

def revoke_token(token, token_hint_type=None):
    """Revoca un token (access token o refresh token)."""
    params = {"token": token}
    if token_hint_type:
        params["token_hint_type"] = token_hint_type
    print(f"https://id.kick.com/oauth/revoke?{urlencode(params)}")
    response = requests.post(f"https://id.kick.com/oauth/revoke?{urlencode(params)}")

    if response.status_code == 200:
        print("Token revocado correctamente.")
    else:
        print(f"Error al revocar el token: {response.status_code} - {response.text}")

#########################################################

@app.route("/")
def index():
    auth_url, code_verifier, state = get_authorization_url()
    session["code_verifier"] = code_verifier # Guarda code_verifier en la sesión
    session["state"] = state # Guarda state en la sesión
    print("state: ",session["state"])
    return f'<a href="{auth_url}">Autorizar con Kick</a>'

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    print("request.args.get('code'): ", request.args.get("code"))
    print("session.get('state'): ", session.get("state"))
    print("request.args.get('state'): ", request.args.get("state"))
    print(session)
    print("Contenido de la sesión:")
    for clave, valor in session.items():
        print(f"{clave}: {valor}")
    if state != session.get("state"):  # ¡Verificación del estado!
        return "Error: Estado no válido", 400

    if code:
        token_data = get_access_token(code, session.get("code_verifier"))
        if token_data:
            session["access_token"] = token_data["access_token"]
            session["refresh_token"] = token_data["refresh_token"]
            return redirect(url_for("success")) # Redirige a una página de éxito
        else:
            return "Error al obtener el token"
    else:
        return "Error: No se recibió el código de autorización"


@app.route("/success") # Página de éxito
def success():
    access_token = session.get("access_token")
    if access_token:
        response = requests.get(
            "https://api.kick.com/public/v1/categories?q=ga%",
            headers={"Authorization": f"Bearer {access_token}"}, # Usa Bearer token
        )
        data = response.json()
        print("Datos de la API:\n", data)
        return f"Datos de la API: {data}"  # Muestra los datos
    
    else:
        return "No hay token de acceso"

if __name__ == "__main__":
    try:
        print("La aplicación Flask se ha iniciado correctamente.")  # Mensaje en la consola
        app.run(debug=True, port=5001)
    except Exception as e:
        print(f"Error al iniciar la aplicación: {e}")
        import traceback
        traceback.print_exc()
