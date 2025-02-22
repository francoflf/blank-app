import requests
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from flask import Flask, request, redirect, url_for, session, jsonify
from flask_session import Session 
import json
import redis

# Datos de tu aplicación
CLIENT_ID = "01JMMS7DVKKB10JM3KHCMCQ355"
CLIENT_SECRET = "29ccdadaac0c46088f55f75edc11d7c559db8f0c5a8c1f2e79793f7e9f8d1848"
# REDIRECT_URI = "https://blank-app-7n69k0rfqzl.streamlit.app"
REDIRECT_URI = "https://localhost:443/callback"
print(f"REDIRECT_URI en Flask: {REDIRECT_URI}")

SCOPES = "user:read channel:read"

app = Flask(__name__)  # ¡Instancia de la aplicación creada *fuera* del if

# 🔹 1️⃣ Agregar SECRET_KEY para firmar sesiones
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)  

# 🔹 2️⃣ Configuración de sesión y cookies
app.config['SESSION_TYPE'] = 'redis'  # Usa archivos para almacenamiento de sesión
app.config['SESSION_PERMANENT'] = False  
app.config['SESSION_USE_SIGNER'] = True  # Protege contra manipulación de sesiones
app.config['SESSION_COOKIE_NAME'] = 'session'  
app.config['SESSION_COOKIE_HTTPONLY'] = True    
app.config['SESSION_COOKIE_SECURE'] = True  # Cambiar a True en producción (HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Permite redirección OAuth sin perder sesión

# ⚠️ Necesitas instalar Redis localmente o usar un servicio de Redis en producción
app.config['SESSION_REDIS'] = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

Session(app)  # 🔹 Inicializar Flask-Session

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
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(16)
    

    session["code_verifier"] = code_verifier
    session["state"] = state  # Guarda el state en la sesión
    session.modified = True  # 🔹 Asegura que Flask guarda la sesión antes de la redirección
    #session.save()  # 🔹 Fuerza el guardado

    print(f"State guardado en sesión: {state}")  # Depuración adicional

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
    print(f"State generado: {state}")
    print(f"Session state (antes de redirigir): {session.get('state')}")
    print(f"URL de autorización: {authorization_url}") # Imprime la URL completa

    return f'<a href="{authorization_url}">Autorizar con Kick</a>'

@app.route("/callback")  # Nueva ruta para el callback de Kick
def callback():
    print(f"URL de Callback (navegador): {request.url}") # Imprime la URL completa del callback
    print(f"Session state (al entrar en callback): {session.get('state')}")
    print(f"Session state en callback (antes de verificar): {session.get('state')}")
    code = request.args.get("code")
    state = request.args.get("state")
    print(f"Code recibido: {code}")
    print(f"State recibido: {state}")
    print(f"Session state: {session.get('state')}")

    if state != session.get("state"):
        return "Error: Estado no coincide", 400

    code_verifier = session.get("code_verifier")
    token_data = get_access_token(code, code_verifier)

    if token_data:
        session["access_token"] = token_data["access_token"]
        session["refresh_token"] = token_data.get("refresh_token") # Guarda el refresh token
        return redirect(url_for("get_categories")) # Redirige a la función para obtener categorías
    else:
        return "Error al obtener el token", 400


@app.route("/get_categories")
def get_categories():
    access_token = session.get("access_token")

    if not access_token:
        return "No hay token de acceso. Debes autorizar primero.", 401

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get("https://api.kick.com/public/v1/categories", headers=headers) # Eliminé el q=ga% para traer todas las categorías
        response.raise_for_status()  # Lanza una excepción para códigos de error HTTP
        data = response.json()

        # Guardar en archivo .txt
        with open("categories.txt", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)  # Guarda el JSON formateado

        return "Categorías obtenidas y guardadas en categories.txt"

    except requests.exceptions.RequestException as e:
        return f"Error al obtener categorías: {e}", 500
    except Exception as e: # Captura cualquier otro error
      return f"Error inesperado: {e}", 500

if __name__ == "__main__":
    app.run(debug=True, port=443, ssl_context=('.certs/cert.pem', '.certs/key.pem'))

