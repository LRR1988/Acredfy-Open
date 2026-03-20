"""
Modulo de autenticacion y licencias para Acredfy.

Gestiona la activacion, verificacion y cache de licencias
vinculadas a la maquina del usuario.
"""

import base64
import hashlib
import json
import os
import platform
import socket
import winreg
from datetime import datetime, timedelta, timezone

import requests

from . import config


# ---------------------------------------------------------------------------
# Excepcion personalizada
# ---------------------------------------------------------------------------

class LicenseError(Exception):
    """Error relacionado con la licencia del producto."""
    pass


# ---------------------------------------------------------------------------
# Identificacion de maquina
# ---------------------------------------------------------------------------

def get_machine_id() -> str:
    """Genera un ID unico de maquina basado en el MachineGuid de Windows
    y el nombre del equipo.  Devuelve un hash SHA-256 en hexadecimal."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
    except OSError:
        raise LicenseError(
            "No se pudo leer el identificador de la maquina. "
            "Asegurese de ejecutar en Windows con permisos adecuados."
        )

    hostname = socket.gethostname()
    raw = f"{machine_guid}|{hostname}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_machine_name() -> str:
    """Devuelve un nombre legible del equipo (hostname)."""
    return socket.gethostname()


# ---------------------------------------------------------------------------
# Ofuscacion sencilla del archivo de autenticacion  (XOR + base64)
# ---------------------------------------------------------------------------

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR ciclico de *data* con *key*."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _save_auth(data: dict) -> None:
    """Guarda *data* (dict JSON-serializable) en AUTH_FILE ofuscado."""
    machine_id = get_machine_id()
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    xored = _xor_bytes(raw, machine_id.encode("utf-8"))
    encoded = base64.b64encode(xored)

    auth_dir = os.path.dirname(config.AUTH_FILE)
    if auth_dir and not os.path.isdir(auth_dir):
        os.makedirs(auth_dir, exist_ok=True)

    with open(config.AUTH_FILE, "wb") as f:
        f.write(encoded)


def _load_auth() -> dict | None:
    """Lee y descifra AUTH_FILE.  Devuelve *None* si no existe o es invalido."""
    if not os.path.isfile(config.AUTH_FILE):
        return None

    try:
        with open(config.AUTH_FILE, "rb") as f:
            encoded = f.read()

        machine_id = get_machine_id()
        xored = base64.b64decode(encoded)
        raw = _xor_bytes(xored, machine_id.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers HTTP
# ---------------------------------------------------------------------------

def _api_url(endpoint: str) -> str:
    """Construye la URL completa para un endpoint de la API."""
    base = config.API_BASE_URL.rstrip("/")
    return f"{base}/{endpoint.lstrip('/')}"


def _post(endpoint: str, payload: dict, timeout: int = 15) -> dict:
    """POST JSON al endpoint y devuelve el cuerpo de la respuesta como dict."""
    try:
        resp = requests.post(
            _api_url(endpoint),
            json=payload,
            timeout=timeout,
        )
    except requests.ConnectionError:
        raise LicenseError(
            "No se pudo conectar con el servidor de licencias. "
            "Compruebe su conexion a Internet."
        )
    except requests.Timeout:
        raise LicenseError(
            "El servidor de licencias no responde. Intentelo mas tarde."
        )
    except requests.RequestException as exc:
        raise LicenseError(f"Error de red: {exc}")

    if resp.status_code == 200:
        return resp.json()

    # Intentar extraer mensaje del servidor
    try:
        body = resp.json()
        msg = body.get("error") or body.get("message") or body.get("detail")
    except Exception:
        msg = None

    if resp.status_code == 401:
        raise LicenseError(msg or "Clave de licencia no valida.")
    if resp.status_code == 403:
        raise LicenseError(msg or "Licencia ya activada en otra maquina.")
    if resp.status_code == 409:
        raise LicenseError(msg or "Conflicto: la licencia ya esta en uso.")
    if resp.status_code == 410:
        raise LicenseError(msg or "La licencia ha expirado.")
    if resp.status_code == 429:
        raise LicenseError(msg or "Demasiados intentos. Espere unos minutos.")

    raise LicenseError(
        msg or f"Error del servidor (codigo {resp.status_code}). "
               "Intentelo mas tarde."
    )


def _delete(endpoint: str, payload: dict, timeout: int = 15) -> None:
    """DELETE JSON al endpoint."""
    try:
        resp = requests.delete(
            _api_url(endpoint),
            json=payload,
            timeout=timeout,
        )
    except requests.ConnectionError:
        raise LicenseError(
            "No se pudo conectar con el servidor de licencias. "
            "Compruebe su conexion a Internet."
        )
    except requests.Timeout:
        raise LicenseError(
            "El servidor de licencias no responde. Intentelo mas tarde."
        )
    except requests.RequestException as exc:
        raise LicenseError(f"Error de red: {exc}")

    if resp.status_code not in (200, 204):
        try:
            body = resp.json()
            msg = body.get("error") or body.get("message") or body.get("detail")
        except Exception:
            msg = None
        raise LicenseError(
            msg or f"Error al desactivar la licencia (codigo {resp.status_code})."
        )


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

def activate(license_key: str) -> dict:
    """Activa una licencia en esta maquina.

    Envia la clave al servidor, guarda el token recibido y devuelve
    un dict con {token, expires_at, company}.

    Raises:
        LicenseError: si la clave es invalida, la licencia esta en uso, etc.
    """
    if not license_key or not license_key.strip():
        raise LicenseError("Debe introducir una clave de licencia.")

    machine_id = get_machine_id()
    machine_name = _get_machine_name()

    result = _post("activate", {
        "license_key": license_key.strip(),
        "machine_id": machine_id,
        "machine_name": machine_name,
    })

    # Construir datos a persistir
    auth_data = {
        "token": result["token"],
        "expires_at": result["expires_at"],
        "company": result.get("company", ""),
        "activated_at": datetime.now(timezone.utc).isoformat(),
    }

    _save_auth(auth_data)
    return auth_data


def verify() -> dict:
    """Verifica y refresca el token con el servidor.

    Devuelve los datos de autenticacion actualizados.

    Raises:
        LicenseError: si no hay licencia guardada o el servidor la rechaza.
    """
    auth = _load_auth()
    if auth is None:
        raise LicenseError("No hay ninguna licencia activada en esta maquina.")

    token = auth.get("token")
    if not token:
        raise LicenseError("Datos de licencia corruptos. Reactive la licencia.")

    machine_id = get_machine_id()

    result = _post("verify", {
        "token": token,
        "machine_id": machine_id,
    })

    # Actualizar datos locales con la respuesta del servidor
    auth["token"] = result.get("token", token)
    if "expires_at" in result:
        auth["expires_at"] = result["expires_at"]
    if "company" in result:
        auth["company"] = result["company"]

    _save_auth(auth)
    return auth


def is_licensed() -> bool:
    """Comprueba si la maquina tiene una licencia valida.

    - Si el token existe y no ha expirado: True.
    - Si ha expirado pero estamos dentro del periodo de gracia
      (LICENSE_CACHE_DAYS, 7 dias por defecto), intenta verificar
      online; si no hay red, permite el uso.
    - Si ha superado el periodo de gracia: False.
    """
    auth = _load_auth()
    if auth is None:
        return False

    token = auth.get("token")
    expires_at_str = auth.get("expires_at")
    if not token or not expires_at_str:
        return False

    # Parsear fecha de expiracion
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        # Asegurar que es aware (UTC)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return False

    now = datetime.now(timezone.utc)

    # Token vigente
    if now < expires_at:
        return True

    # Token expirado: comprobar periodo de gracia
    cache_days = getattr(config, "LICENSE_CACHE_DAYS", 7)
    grace_limit = expires_at + timedelta(days=cache_days)

    if now > grace_limit:
        # Fuera del periodo de gracia
        return False

    # Dentro del periodo de gracia: intentar renovar online
    try:
        verify()
        return True
    except LicenseError:
        # Sin conexion u otro error — permitir uso offline
        return True


def get_license_info() -> dict | None:
    """Devuelve los datos de la licencia guardada, o None si no hay."""
    return _load_auth()


def deactivate() -> None:
    """Desactiva la licencia en el servidor y elimina los datos locales.

    Raises:
        LicenseError: si no hay licencia o el servidor rechaza la peticion.
    """
    auth = _load_auth()
    if auth is None:
        raise LicenseError("No hay ninguna licencia activada en esta maquina.")

    token = auth.get("token")
    if not token:
        raise LicenseError("Datos de licencia corruptos.")

    machine_id = get_machine_id()

    _delete("deactivate", {
        "token": token,
        "machine_id": machine_id,
    })

    # Eliminar archivo local
    try:
        if os.path.isfile(config.AUTH_FILE):
            os.remove(config.AUTH_FILE)
    except OSError:
        pass


def _get_authenticated(endpoint: str, timeout: int = 15) -> dict:
    """GET con token JWT en Authorization header."""
    auth = _load_auth()
    if not auth or not auth.get("token"):
        raise LicenseError("No hay licencia activada.")
    try:
        resp = requests.get(
            _api_url(endpoint),
            headers={"Authorization": f"Bearer {auth['token']}"},
            timeout=timeout,
        )
    except requests.ConnectionError:
        raise LicenseError("No se pudo conectar con el servidor.")
    except requests.Timeout:
        raise LicenseError("El servidor no responde.")
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 401:
        raise LicenseError("Sesion expirada. Reinicie la aplicacion.")
    raise LicenseError(f"Error del servidor (codigo {resp.status_code}).")


def _post_authenticated(endpoint: str, payload: dict, timeout: int = 15) -> dict:
    """POST con token JWT en Authorization header."""
    auth = _load_auth()
    if not auth or not auth.get("token"):
        raise LicenseError("No hay licencia activada.")
    try:
        resp = requests.post(
            _api_url(endpoint),
            json=payload,
            headers={"Authorization": f"Bearer {auth['token']}"},
            timeout=timeout,
        )
    except requests.ConnectionError:
        raise LicenseError("No se pudo conectar con el servidor.")
    except requests.Timeout:
        raise LicenseError("El servidor no responde.")
    if resp.status_code in (200, 201):
        return resp.json()
    if resp.status_code == 401:
        raise LicenseError("Sesion expirada. Reinicie la aplicacion.")
    raise LicenseError(f"Error del servidor (codigo {resp.status_code}).")
