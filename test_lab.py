"""Regresiones funcionales y de seguridad de la versión corregida."""
from contextlib import contextmanager
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash
import app as parking


@contextmanager
def payment_server(status=200, body=b"RECIBO_CONTROLADO_OK"):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "http://127.0.0.1:1/no-se-debe-consultar")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            return
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch.dict(parking.app.config, PAYMENT_PORT=server.server_port):
            yield f"http://127.0.0.1:{server.server_port}/recibo.txt", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = secrets.token_urlsafe(24)
        cls.camera_key = secrets.token_urlsafe(32)
        cls.password_hash = generate_password_hash(cls.password)

    def setUp(self):
        self.config = patch.dict(parking.app.config, TESTING=True,
                                 ADMIN_PASSWORD_HASH=self.password_hash,
                                 CAMERA_API_KEY=self.camera_key)
        self.config.start()
        self.addCleanup(self.config.stop)
        parking.db.close()
        parking.db = parking.database()
        self.client = parking.app.test_client()

    def test_entrada_duplicados_y_cobro(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.client.post("/entrada", data={"placa": "abc-123"})
        self.client.post("/entrada", data={"placa": "ABC-123"})
        self.assertEqual(parking.db.execute("SELECT count(*) FROM tickets").fetchone()[0], 1)
        self.assertEqual(parking.db.execute("SELECT placa FROM tickets").fetchone()[0], "ABC-123")
        self.assertIn(b"$1.50", self.client.post("/salida", data={"ticket": "1"}).data)
        self.assertEqual(parking.db.execute("SELECT total FROM tickets").fetchone()[0], 1.5)
        self.assertIn(b"Ticket activo no encontrado", self.client.post("/salida", data={"ticket": "1"}).data)

    def test_capacidad_placa_y_reutilizacion(self):
        self.client.post("/entrada", data={"placa": "<script>"})
        for n in range(12):
            self.client.post("/entrada", data={"placa": f"LAB-{n:03d}"})
        self.assertIn(b"Parqueo completo", self.client.post("/entrada", data={"placa": "EXTRA-1"}).data)
        self.client.post("/salida", data={"ticket": "1"})
        self.client.post("/entrada", data={"placa": "EXTRA-1"})
        self.assertEqual(parking.db.execute("SELECT espacio FROM tickets WHERE placa='EXTRA-1'").fetchone()[0], 1)

    def test_redondeo_horas(self):
        self.client.post("/entrada", data={"placa": "ABC-123"})
        before = (datetime.now()-timedelta(hours=1, minutes=10)).isoformat()
        parking.db.execute("UPDATE tickets SET entrada=? WHERE id=1", (before,))
        parking.db.commit()
        self.assertIn(b"$3.00", self.client.post("/salida", data={"ticket": "1"}).data)

    def test_credenciales_validas_y_hash(self):
        stored = parking.db.execute("SELECT contrasena_hash FROM administradores").fetchone()[0]
        self.assertNotEqual(stored, self.password)
        self.assertIn(b"Acceso concedido", self.client.post("/login", data={"usuario": "admin", "contrasena": self.password}).data)
        self.assertEqual(self.client.get("/api/camara", headers={"X-Camera-Key": self.camera_key}).status_code, 200)

    def test_claves_incorrectas_y_ausentes(self):
        for key in [None, "", secrets.token_urlsafe(24)]:
            headers = {} if key is None else {"X-Camera-Key": key}
            self.assertEqual(self.client.get("/api/camara", headers=headers).status_code, 401)
        with patch.dict(parking.app.config, CAMERA_API_KEY="", ADMIN_PASSWORD_HASH=""):
            self.assertEqual(self.client.get("/api/camara").status_code, 503)
            self.assertEqual(self.client.get("/api/camara", headers={"X-Camera-Key": ""}).status_code, 503)
            self.assertEqual(self.client.post("/login", data={"usuario": "admin", "contrasena": self.password}).status_code, 503)

    def test_sqli_bloqueada(self):
        cases = [("admin' -- ", "x"), ("' OR 1=1 -- ", "x"), ("admin", "' OR '1'='1"), ("nadie", self.password)]
        for usuario, password in cases:
            with self.subTest(usuario=usuario):
                result = self.client.post("/login", data={"usuario": usuario, "contrasena": password})
                self.assertIn(b"Acceso denegado", result.data)
                self.assertNotIn(b"Acceso concedido", result.data)

    def test_xss_escapado(self):
        for payload in ["<script>alert(1)</script>", '<img src=x onerror="alert(1)">']:
            result = self.client.get("/buscar_placa", query_string={"placa": payload})
            self.assertNotIn(payload.encode(), result.data)
            self.assertIn(b"&lt;", result.data)
        self.assertIn(b"<b>ABC-123</b>", self.client.get("/buscar_placa", query_string={"placa": "ABC-123"}).data)

    def test_comandos_maliciosos_no_se_ejecutan(self):
        with patch.object(parking.subprocess, "run") as runner:
            for value in ["127.0.0.1 & echo CMD_DEMO_OK", "127.0.0.1; echo DEMO", "127.0.0.1\nwhoami", "-n 100", "localhost", "::1%lo"]:
                self.assertEqual(self.client.post("/ping_camara", data={"ip": value}).status_code, 400)
            runner.assert_not_called()

    def test_diagnostico_legitimo_sin_shell(self):
        for ip in ["127.0.0.1", "::1"]:
            with patch.object(parking.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "CAMARA_OK", "")) as runner:
                self.assertIn(b"CAMARA_OK", self.client.post("/ping_camara", data={"ip": ip}).data)
                args, kwargs = runner.call_args
                self.assertIs(kwargs["shell"], False)
                self.assertEqual(args[0][-1], ip)
                self.assertEqual(args[0][0], "ping")
                self.assertIn("-n" if parking.os.name == "nt" else "-c", args[0])

    def test_diagnostico_maneja_errores(self):
        for error in [OSError(), subprocess.TimeoutExpired("ping", 4)]:
            with patch.object(parking.subprocess, "run", side_effect=error):
                self.assertEqual(self.client.post("/ping_camara", data={"ip": "127.0.0.1"}).status_code, 200)

    def test_log_normal_y_rutas_rechazadas(self):
        self.assertIn(b"Barrera de entrada", self.client.get("/ver_log").data)
        for value in ["../fixtures/nota-interna.txt", "..\\fixtures\\nota-interna.txt", "C:\\Windows\\win.ini", "\\\\localhost\\share\\archivo", "barrera.log:stream", "C:archivo", "/etc/passwd", "CON"]:
            result = self.client.get("/ver_log", query_string={"file": value})
            self.assertEqual(result.status_code, 400)
            self.assertNotIn(b"TRAVERSAL_DEMO_OK", result.data)

    def test_log_enlace_externo_rechazado(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "logs").mkdir()
            external = base / "external.txt"
            external.write_text("EXTERNAL_DEMO", encoding="utf-8")
            # El resolvedor representa el resultado de un enlace fuera de logs.
            real_resolve = Path.resolve
            def resolve(path, *args, **kwargs):
                if path == base / "logs" / "barrera.log":
                    return external
                return real_resolve(path, *args, **kwargs)
            with patch.object(parking, "BASE", base), patch.object(Path, "resolve", resolve):
                self.assertEqual(self.client.get("/ver_log").status_code, 400)

    def test_pago_destino_legitimo(self):
        with payment_server() as (url, requests):
            result = self.client.post("/validar_pago", data={"url": url})
            self.assertEqual(result.status_code, 200)
            self.assertIn(b"RECIBO_CONTROLADO_OK", result.data)
            self.assertEqual(requests, ["/recibo.txt"])

    def test_ssrf_rechaza_destinos_y_esquemas(self):
        with patch.object(parking.http.client, "HTTPConnection") as connection:
            for url in ["http://127.0.0.1:5002/recibo.txt", "http://localhost:5001/recibo.txt", "http://example.com/", "file:///etc/passwd", "http://127.0.0.1:5001/recibo.txt?x=1", "http://127.0.0.1:5001/recibo.txt#x", "http://user@127.0.0.1:5001/recibo.txt", "http://127.0.0.1:5001/otro"]:
                self.assertEqual(self.client.post("/validar_pago", data={"url": url}).status_code, 400)
            connection.assert_not_called()

    def test_pago_no_sigue_redirecciones(self):
        with payment_server(status=302) as (url, requests), patch.object(parking.http.client, "HTTPConnection", wraps=parking.http.client.HTTPConnection) as connection:
            self.assertEqual(self.client.post("/validar_pago", data={"url": url}).status_code, 502)
            self.assertEqual(requests, ["/recibo.txt"])
            self.assertEqual(connection.call_count, 1)

    def test_pago_limita_respuesta_y_escapa_html(self):
        with payment_server(body=b"x" * 16001) as (url, _):
            self.assertEqual(self.client.post("/validar_pago", data={"url": url}).status_code, 502)
        with payment_server(body=b"<script>alert(1)</script>") as (url, _):
            result = self.client.post("/validar_pago", data={"url": url})
            self.assertNotIn(b"<script>alert(1)</script>", result.data)
            self.assertIn(b"&lt;script&gt;", result.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
