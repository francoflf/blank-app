from flask import Flask, session

app = Flask(__name__)
app.secret_key = "mi_clave_secreta"  # ¡Recuerda cambiar esto por una clave segura!

@app.route("/")
def index():
    session["estado"] = "valor_de_prueba"
    return "Estado guardado"

@app.route("/verificar")
def verificar():
    estado = session.get("estado")
    print(session.get("estado"))
    print(session["estado"])
    if estado == "valor_de_prueba":
        return "Estado válido"
    else:
        return "Estado no válido"

if __name__ == "__main__":
    app.run(debug=True)