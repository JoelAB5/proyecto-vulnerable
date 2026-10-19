# Smart Parking — versión corregida

Aplicación local en Flask con 12 espacios, entradas, salidas, historial y tarifa
de $1.50 por hora iniciada. Los tickets se guardan en memoria y se borran al
reiniciar. La comprobación del operador es demostrativa; no crea una sesión
ni restringe el panel. Esta sigue siendo una práctica local con datos ficticios.

## Iniciar (PowerShell)

```powershell
python -m pip install -r requirements.txt
python configurar.py
python app.py
```

La configuración solicita una contraseña propia de al menos 12 caracteres y
confirmación. El usuario es `admin`. Guarda su hash y una clave de cámara
aleatoria en `instance/local.json`, excluido de Git. No sobrescribe una
configuración existente. No hay contraseña ni clave predeterminadas. Reinicia
el servidor tras configurar. Sin configuración, login y API de cámara responden
503. También puedes proporcionar `ADMIN_PASSWORD_HASH` y `CAMERA_API_KEY`
mediante el entorno; la primera debe ser un hash compatible con Werkzeug.

Abre http://127.0.0.1:5000. La API de cámara sigue usando la cabecera
`X-Camera-Key`, cuyo valor está en la configuración privada local.

Para la integración simulada de comprobantes, en otra terminal:

```powershell
python -m http.server 5001 --bind 127.0.0.1 --directory fixtures
```

## Correcciones aplicadas

| Caso anterior | Control de la versión corregida |
|---|---|
| Credenciales incrustadas | Configuración privada por equipo, clave aleatoria y hash de contraseña |
| SQL Injection | Usuario consultado con parámetros; contraseña verificada contra el hash |
| XSS reflejado | HTML estático en Jinja y escape automático de la matrícula; se eliminó safe |
| Inyección de comandos | Solo cámaras de demo registradas (127.0.0.1 y ::1), argumentos fijos y shell=False |
| Path Traversal | Únicamente barrera.log, ruta resuelta dentro de logs y rechazo de enlaces externos |
| SSRF | Únicamente http://127.0.0.1:5001/recibo.txt; la petición usa host/puerto/ruta del servidor, sin redirecciones ni proxies |

Las claves antiguas ya no dan acceso. No se ocultaron hallazgos con comentarios
`nosemgrep` ni se desactivaron reglas. Los registros y comprobantes siguen
mostrándose como texto escapado. El servicio de pago de demo utiliza HTTP
exclusivamente hacia loopback; no es una pasarela real ni procesa cobros.

## Pruebas

```powershell
python -m unittest -v test_lab.py
```

Las pruebas verifican rechazo de payloads de SQL, XSS, comandos, rutas y URLs,
configuración ausente, credenciales válidas, redirecciones, límites de respuesta,
capacidad, duplicados, reutilización de espacios y cobros. No necesitan que el
servidor Flask esté encendido. Las pruebas HTTP crean un servidor temporal local.

## Comparar en Semgrep web

Sube esta versión y ejecuta un nuevo escaneo completo basado en reglas sobre
`main`. En Code selecciona este proyecto y estado Open para la captura del
después. Las alertas históricas pueden permanecer en Fixed; eso permite comparar
con la captura anterior. Un escaneo sin hallazgos no certifica ausencia de todos
los problemas de seguridad de un prototipo.
