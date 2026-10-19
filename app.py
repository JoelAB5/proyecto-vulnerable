"""Smart Parking: laboratorio local con seis vulnerabilidades intencionales."""
from datetime import datetime
from pathlib import Path
import math
import os
import re
import sqlite3
import subprocess
import urllib.request

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
TARIFA = 1.50

# V01 / CWE-798: credenciales incrustadas, ficticias y exclusivas del laboratorio.
CAMERA_API_KEY = "parking-demo-secret-2026"
ADMIN_PASSWORD = "parqueo123"


def database():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE administradores (usuario TEXT, contrasena TEXT)")
    conn.execute("INSERT INTO administradores VALUES (?, ?)", ("admin", ADMIN_PASSWORD))
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
    # V02 / CWE-89: entrada del usuario concatenada en una consulta SQL.
    query = f"SELECT usuario FROM administradores WHERE usuario='{usuario}' AND contrasena='{contrasena}'"
    try:
        admin = db.execute(query).fetchone()
        mensaje = f"Acceso concedido: {admin[0]}" if admin else "Acceso denegado"
    except sqlite3.Error:
        mensaje = "Consulta de acceso inválida"
    return page(login_msg=mensaje)


@app.get("/buscar_placa")
def buscar_placa():
    placa = request.args.get("placa", "")
    # V03 / CWE-79: index.html usa |safe y permite ejecutar HTML/JavaScript.
    resultado = f"Consulta de matrícula: <b>{placa}</b>"
    return page(search_result=resultado)


@app.post("/ping_camara")
def ping_camara():
    ip = request.form.get("ip", "127.0.0.1")
    flags = "-n 1 -w 1000" if os.name == "nt" else "-c 1 -W 1"
    # V04 / CWE-78: el shell interpreta el parámetro sin escapar.
    try:
        result = subprocess.run(f"ping {flags} {ip}", shell=True, capture_output=True,
                                text=True, errors="replace", timeout=4)
        salida = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        salida = "Tiempo de diagnóstico agotado."
    return page(ping_result=salida)


@app.get("/ver_log")
def ver_log():
    filename = request.args.get("file", "barrera.log")
    # V05 / CWE-22: ../ permite salir del directorio logs.
    try:
        with open(BASE / "logs" / filename, encoding="utf-8") as archivo:
            contenido = archivo.read(16000)
    except (OSError, UnicodeError):
        contenido = "No se pudo leer el archivo."
    return page(file_result=contenido)


@app.post("/validar_pago")
def validar_pago():
    url = request.form.get("url", "")
    # V06 / CWE-918: destino controlado por el cliente sin lista de permitidos.
    try:
        with urllib.request.urlopen(url, timeout=3) as respuesta:
            contenido = respuesta.read(16000).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        contenido = "No se pudo consultar el comprobante."
    return page(ssrf_result=contenido)


@app.get("/api/camara")
def camara():
    if request.headers.get("X-Camera-Key") != CAMERA_API_KEY:
        return jsonify(error="Clave de cámara requerida"), 401
    return jsonify(camara="LPR-DEMO-01", estado="operativa", barrera="cerrada")


if __name__ == "__main__":
    print("Laboratorio vulnerable: http://127.0.0.1:5000 — solo datos ficticios")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)
