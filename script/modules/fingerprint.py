"""
===============================================================================
 modules/fingerprint.py
 -----------------------------------------------------------------------------
 Identificación del tipo de dispositivo mediante heurísticas combinadas:
   - Prefijo OUI de la MAC (IEEE: primeros 3 octetos)
   - Hostname (DNS inverso)
   - Patrones de puertos abiertos
   - Banners de servicios

 Se asigna también un "riesgo de tipo" (bajo/medio/alto) que indica cuánto
 impacto tiene comprometer ese tipo de dispositivo. Un router o NAS tienen
 impacto alto (control total de la red o datos), mientras que una bombilla
 Hue tiene impacto bajo.
===============================================================================
"""
from typing import Tuple, List
from core import IOT_FINGERPRINTS, Device
from core.config import IOT_FINGERPRINTS as FP


def lookup_vendor_by_mac(mac: str) -> str:
    """Consulta el fabricante por el prefijo OUI de la MAC."""
    if not mac or len(mac) < 8:
        return ""
    prefix = mac.upper()[:8]
    return FP["oui"].get(prefix, "")


def guess_device_type(hostname: str, vendor: str,
                      open_ports: List[int],
                      banners: List[str] = None) -> Tuple[str, str]:
    """
    Adivina el tipo de dispositivo combinando pistas.

    Returns:
        (tipo_dispositivo, riesgo_tipo)
    """
    text = (hostname + " " + vendor + " " + " ".join(banners or "")).lower()

    # 1. Match directo por hostname/vendor
    for keyword, (dtype, risk) in FP["hostname"].items():
        if keyword in text:
            return dtype, risk

    # 2. Heurísticas por combinación de puertos
    ports = set(open_ports)

    # Router/Gateway: DHCP + DNS + web admin
    if 53 in ports and (67 in ports or 68 in ports):
        return "Router / Gateway", "alto"

    # TR-069 es un identificador casi perfecto de router residencial
    if 7547 in ports:
        return "Router doméstico (TR-069)", "alto"

    # Cámara IP: RTSP + web
    if 554 in ports and (80 in ports or 8080 in ports):
        return "Cámara IP (RTSP)", "alto"

    # Impresora
    if 9100 in ports or (631 in ports and 515 in ports):
        return "Impresora de red", "medio"

    # NAS
    if 5000 in ports and 445 in ports:
        return "NAS (Synology?)", "alto"

    # Broker MQTT (domótica)
    if 1883 in ports or 8883 in ports:
        return "Broker MQTT (IoT)", "medio"

    # Plex/Media Server
    if 32400 in ports:
        return "Servidor Plex", "medio"

    # Windows
    if 3389 in ports or (445 in ports and 135 in ports):
        return "Equipo Windows", "medio"

    # Servidor genérico (SSH + HTTP)
    if 22 in ports and (80 in ports or 443 in ports):
        return "Servidor Linux / Headless", "medio"

    # Sólo HTTP → probablemente IoT con panel web
    if (80 in ports or 8080 in ports) and 22 not in ports:
        return "Dispositivo IoT (panel web)", "medio"

    # Chromecast / AirPlay
    if 8009 in ports or 5353 in ports:
        return "Dispositivo multimedia (Cast)", "bajo"

    return "Desconocido", "bajo"


def fingerprint_device(device: Device) -> None:
    """
    Rellena los campos device_type y type_risk de un Device a partir
    de la info ya recolectada (mac, hostname, puertos, banners).
    Modifica el Device in-place.
    """
    # Vendor por OUI
    if not device.vendor:
        device.vendor = lookup_vendor_by_mac(device.mac)

    banners = [s.banner for s in device.services.values() if s.banner]
    dtype, risk = guess_device_type(
        device.hostname, device.vendor, device.open_ports, banners)
    device.device_type = dtype
    device.type_risk = risk


# ============================================================================
#  ADIVINANZA DEL SO
# ============================================================================
def guess_os(device: Device) -> str:
    """
    Adivina el sistema operativo basándose en puertos y banners.
    """
    banners = " ".join(s.banner for s in device.services.values()).lower()
    ports = set(device.open_ports)

    if "ubuntu" in banners:
        return "Linux (Ubuntu)"
    if "debian" in banners:
        return "Linux (Debian)"
    if "raspbian" in banners or device.vendor == "Raspberry Pi":
        return "Linux (Raspberry Pi OS)"
    if "centos" in banners or "red hat" in banners or "rhel" in banners:
        return "Linux (RHEL/CentOS)"
    if "microsoft-iis" in banners or 3389 in ports or 445 in ports and 135 in ports:
        return "Windows"
    if "openwrt" in banners or "dd-wrt" in banners:
        return "Router Linux (OpenWrt/DD-WRT)"
    if "busybox" in banners:
        return "Embedded Linux (BusyBox)"
    if "darwin" in banners or "mac os" in banners:
        return "macOS"
    if 22 in ports and ("openssh" in banners):
        return "Linux / Unix"
    if 5353 in ports and device.vendor == "Apple":
        return "macOS / iOS"
    return ""
