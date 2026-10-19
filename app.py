"""Smart Parking: versión corregida del laboratorio local."""
from datetime import datetime
from pathlib import Path
import math
import hmac
import http.client
import json
import os
import re
import sqlite3
import subprocess

from flask import Flask, jsonify, render_template, request
from werkzeug.security import check_password_hash

app = Flask(__name__, instance_relative_config=True)
BASE = Path(__file__).resolve().parent
TARIFA = 1.50

# Configuración privada, creada por configurar.py y excluida de Git.
app.config.from_file("local.json", load=json.load, silent=True)
app.config.update(
    CAMERA_API_KEY=os.environ.get("CAMERA_API_KEY", app.config.get("CAMERA_API_KEY", "")),
    ADMIN_PASSWORD_HASH=os.environ.get("ADMIN_PASSWORD_HASH", app.config.get("ADMIN_PASSWORD_HASH", "")),
    PAYMENT_PORT=5001,
    MAX_CONTENT_LENGTH=16384,
)


def database():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE administradores (usuario TEXT, contrasena_hash TEXT)")
    password_hash = app.config.get("ADMIN_PASSWORD_HASH")
    if password_hash:
        conn.execute("INSERT INTO administradores VALUES (?, ?)", ("admin", password_hash))
    conn.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, placa TEXT, espacio INTEGER, entrada TEXT, salida TEXT, total REAL)")
    conn.commit()
    return conn


db = database()


def page(**context):
    activos = db.execute("SELECT * FROM tickets WHERE salida IS NULL ORDER BY espacio").fetchall()
    historial = db.execute("SELECT * FROM tickets WHERE salida IS NOT NULL ORDER BY id DESC LIMIT 8").fetchall()
    ocupados = {row[2] for row in activos}
    return render_template("index.html", activos=activos, historial=historial,
                           ocupados=ocupados, tarifa=TARIFA, **context)


@app.get("/")
def index():
    return page()


@app.post("/entrada")
def entrada():
    placa = request.form.get("placa", "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9-]{3,12}", placa):
        return page(aviso="Introduce una placa de 3 a 12 letras, números o guiones.")
    if db.execute("SELECT id FROM tickets WHERE placa=? AND salida IS NULL", (placa,)).fetchone():
        return page(aviso="Ese vehículo ya está dentro.")
    ocupados = {r[0] for r in db.execute("SELECT espacio FROM tickets WHERE salida IS NULL")}
    libre = next((n for n in range(1, 13) if n not in ocupados), None)
    if libre is None:
        return page(aviso="Parqueo completo.")
    db.execute("INSERT INTO tickets (placa, espacio, entrada) VALUES (?, ?, ?)",
               (placa, libre, datetime.now().isoformat(timespec="seconds")))
    db.commit()
    return page(aviso=f"Entrada registrada: {placa}, espacio P{libre:02d}.")


@app.post("/salida")
def salida():
    ticket = db.execute("SELECT id, entrada FROM tickets WHERE id=? AND salida IS NULL",
                        (request.form.get("ticket", ""),)).fetchone()
    if not ticket:
        return page(aviso="Ticket activo no encontrado.")
    ahora = datetime.now()
    horas = max(1, math.ceil((ahora - datetime.fromisoformat(ticket[1])).total_seconds() / 3600))
    total = horas * TARIFA
    db.execute("UPDATE tickets SET salida=?, total=? WHERE id=?",
               (ahora.isoformat(timespec="seconds"), total, ticket[0]))
    db.commit()
    return page(aviso=f"Salida registrada. Total: ${total:.2f} ({horas} hora/s).")


@app.post("/login")
def login():
    usuario = request.form.get("usuario", "")
    contrasena = request.form.get("contrasena", "")
    if not app.config.get("ADMIN_PASSWORD_HASH"):
        return page(login_msg="Configura las credenciales con python configurar.py."), 503
    admin = db.execute(
        "SELECT usuario, contrasena_hash FROM administradores WHERE usuario=?", (usuario,)
    ).fetchone()
    try:
        valido = bool(admin and check_password_hash(admin[1], contrasena))
    except (ValueError, TypeError):
        valido = False
    mensaje = f"Acceso concedido: {admin[0]}" if valido else "Acceso denegado"
    return page(login_msg=mensaje)


@app.get("/buscar_placa")
def buscar_placa():
    placa = request.args.get("placa", "")
    # El HTML está en la plantilla; Jinja escapa la entrada automáticamente.
    return page(search_result=placa)


@app.post("/ping_camara")
def ping_camara():
    ip = request.form.get("ip", "127.0.0.1")
    # Cámaras registradas de demostración: el usuario no construye el comando.
    flags = ["-n", "1", "-w", "1000"] if os.name == "nt" else ["-c", "1", "-W", "1"]
    if ip == "127.0.0.1":
        comando = ["ping", *flags, "127.0.0.1"]
    elif ip == "::1":
        comando = ["ping", *flags, "::1"]
    else:
        return page(ping_result="Cámara no registrada. Usa 127.0.0.1 o ::1."), 400
    try:
        result = subprocess.run(comando, shell=False, capture_output=True,
                                text=True, errors="replace", timeout=4)
        salida = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        salida = "Tiempo de diagnóstico agotado."
    except OSError:
        salida = "No se pudo iniciar el diagnóstico de cámara."
    return page(ping_result=salida)


@app.get("/ver_log")
def ver_log():
    filename = request.args.get("file", "barrera.log")
    # Solo el registro publicado; ningún nombre del cliente alcanza open().
    if filename != "barrera.log":
        return page(file_result="Archivo de registro no permitido."), 400
    try:
        log_root = (BASE / "logs").resolve()
        log_path = (log_root / "barrera.log").resolve()
        if not log_path.is_relative_to(log_root) or not log_path.is_file():
            return page(file_result="Archivo de registro no permitido."), 400
        with open(log_path, encoding="utf-8") as archivo:
            contenido = archivo.read(16000)
    except (OSError, UnicodeError):
        contenido = "No se pudo leer el archivo."
    return page(file_result=contenido)


@app.post("/validar_pago")
def validar_pago():
    url = request.form.get("url", "")
    # Integración de demo fija: IP literal y ruta fija, sin proxies ni redirects.
    # El campo URL se conserva para demostrar el rechazo de destinos arbitrarios.
    port = app.config["PAYMENT_PORT"]
    allowed_url = f"http://127.0.0.1:{port}/recibo.txt"
    if url != allowed_url:
        return page(ssrf_result="Destino de comprobante no permitido."), 400
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/recibo.txt")
        respuesta = connection.getresponse()
        if respuesta.status != 200:
            return page(ssrf_result="Respuesta de comprobante no permitida."), 502
        contenido = respuesta.read(16001)
        if len(contenido) > 16000:
            return page(ssrf_result="Comprobante demasiado grande."), 502
        contenido = contenido.decode("utf-8", errors="replace")
    except (OSError, http.client.HTTPException):
        return page(ssrf_result="No se pudo consultar el comprobante."), 502
    finally:
        connection.close()
    return page(ssrf_result=contenido)


@app.get("/api/camara")
def camara():
    configured_key = app.config.get("CAMERA_API_KEY", "")
    if not configured_key:
        return jsonify(error="Configura las credenciales con python configurar.py."), 503
    supplied_key = request.headers.get("X-Camera-Key", "")
    if not hmac.compare_digest(supplied_key.encode("utf-8"), configured_key.encode("utf-8")):
        return jsonify(error="Clave de cámara requerida"), 401
    return jsonify(camara="LPR-DEMO-01", estado="operativa", barrera="cerrada")


if __name__ == "__main__":
    print("Smart Parking corregido: http://127.0.0.1:5000 — solo datos ficticios")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)
