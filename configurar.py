"""Crea credenciales locales propias sin contraseñas fijas ni texto plano."""
import getpass
import json
from pathlib import Path
import secrets

from werkzeug.security import generate_password_hash


def main():
    target = Path(__file__).resolve().parent / "instance" / "local.json"
    if target.exists():
        raise SystemExit("Ya existe instance/local.json. Se conservó la configuración actual.")
    password = getpass.getpass("Nueva contraseña del operador admin (mínimo 12 caracteres): ")
    if len(password) < 12:
        raise SystemExit("La contraseña debe tener al menos 12 caracteres.")
    if password != getpass.getpass("Repite la contraseña: "):
        raise SystemExit("Las contraseñas no coinciden.")
    config = {
        "ADMIN_PASSWORD_HASH": generate_password_hash(password),
        "CAMERA_API_KEY": secrets.token_urlsafe(32),
    }
    target.parent.mkdir(exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
    print("Credenciales guardadas en instance/local.json. No subas ese archivo a GitHub.")
    print("Usuario: admin. La clave aleatoria de cámara está en CAMERA_API_KEY de ese archivo.")


if __name__ == "__main__":
    main()
