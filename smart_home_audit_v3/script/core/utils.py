"""
===============================================================================
 core/utils.py
 -----------------------------------------------------------------------------
 Utilidades compartidas: detección de red, ejecución segura de comandos,
 validaciones, formateos.
===============================================================================
"""
import os
import re
import socket
import ipaddress
import subprocess
from typing import Tuple, Optional
from pathlib import Path


def is_root() -> bool:
    """True si el script se ejecuta como root (Linux)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def check_command(cmd: str) -> bool:
    """Comprueba si un comando del sistema está instalado."""
    try:
        subprocess.run(["which", cmd], capture_output=True, check=True)
        return True
    except Exception:
        return False


def run_command(cmd: list[str], timeout: int = 30,
                capture: bool = True) -> Tuple[int, str, str]:
    """
    Ejecuta un comando de sistema de forma segura.
    Devuelve (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"comando no encontrado: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def get_default_interface() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Detecta la interfaz de red por defecto, su gateway y la red CIDR.
    Devuelve (iface, gateway, cidr_network) o (None, None, None) si falla.
    """
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True).strip()
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if not m:
            return None, None, None
        gateway, iface = m.group(1), m.group(2)

        out2 = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", iface], text=True)
        m2 = re.search(r"inet (\S+)", out2)
        if not m2:
            return iface, gateway, None

        network = str(ipaddress.ip_interface(m2.group(1)).network)
        return iface, gateway, network
    except Exception:
        return None, None, None


def get_local_ip() -> str:
    """IP local del host (la que usa para salir a internet)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_public_ip() -> Optional[str]:
    """IP pública del router (la que ve internet)."""
    import urllib.request
    services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ]
    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                # validamos que sea una IP
                ipaddress.ip_address(ip)
                return ip
        except Exception:
            continue
    return None


def is_valid_cidr(cidr: str) -> bool:
    """Valida que sea un CIDR correcto."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except Exception:
        return False


def normalize_mac(mac: str) -> str:
    """Normaliza una MAC a MAYÚSCULAS con ':'."""
    if not mac:
        return ""
    m = mac.upper().replace("-", ":")
    # formato xx:xx:xx:xx:xx:xx
    if len(m) == 12 and ":" not in m:
        m = ":".join(m[i:i+2] for i in range(0, 12, 2))
    return m


def format_duration(seconds: float) -> str:
    """Formatea una duración en segundos a una cadena humana."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s"


def sort_ips(ips: list[str]) -> list[str]:
    """Ordena una lista de IPs numéricamente."""
    def key(ip):
        try:
            return tuple(int(p) for p in ip.split("."))
        except Exception:
            return (0, 0, 0, 0)
    return sorted(ips, key=key)
