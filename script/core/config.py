"""
===============================================================================
 core/config.py
 -----------------------------------------------------------------------------
 Configuración centralizada de toda la suite de auditoría.
 Todos los parámetros ajustables (timeouts, puertos, rutas, API keys) viven
 aquí para no tener "números mágicos" repartidos por el código.
===============================================================================
"""
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Tuple, List
import os


# ============================================================================
#  RUTAS
# ============================================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
CACHE_DIR = DATA_DIR / "cache"

# Se crean si no existen
for d in (DATA_DIR, REPORTS_DIR, CACHE_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ============================================================================
#  NVD API (Correlación CVE)
# ============================================================================
# Obtén una API key gratuita en: https://nvd.nist.gov/developers/request-an-api-key
# Se puede dejar vacía (funcionará más lento: 6s entre requests en vez de 0.6s)
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_DELAY = 0.6 if NVD_API_KEY else 6.0      # segundos entre llamadas
NVD_TIMEOUT = 30                                      # timeout HTTP
NVD_MAX_RETRIES = 3

CVE_CACHE_DB = CACHE_DIR / "cve_cache.db"
CVE_CACHE_TTL_DAYS = 7                               # días que vive la caché


# ============================================================================
#  ESCANEO DE PUERTOS
# ============================================================================
DEFAULT_PORT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
PORT_SCAN_WORKERS = 80
PING_WORKERS = 100
PING_TIMEOUT = 1


# ============================================================================
#  CATÁLOGO DE PUERTOS CON CLASIFICACIÓN DE SEGURIDAD
# ============================================================================
# Estructura: { puerto: (nombre, descripción, clasificación) }
# Clasificación: SEGURO | NEUTRO | REVISAR | INSEGURO | CRITICO
COMMON_PORTS: Dict[int, Tuple[str, str, str]] = {
    21:   ("FTP",          "File Transfer Protocol",         "INSEGURO"),
    22:   ("SSH",          "Secure Shell",                   "SEGURO"),
    23:   ("Telnet",       "Telnet (texto plano)",           "CRITICO"),
    25:   ("SMTP",         "Simple Mail Transfer",           "REVISAR"),
    53:   ("DNS",          "Domain Name System",             "NEUTRO"),
    67:   ("DHCP",         "DHCP Server",                    "NEUTRO"),
    68:   ("DHCP",         "DHCP Client",                    "NEUTRO"),
    69:   ("TFTP",         "Trivial FTP",                    "CRITICO"),
    80:   ("HTTP",         "Web sin cifrar",                 "INSEGURO"),
    110:  ("POP3",         "POP3 sin cifrar",                "INSEGURO"),
    111:  ("RPCbind",      "Portmapper",                     "REVISAR"),
    123:  ("NTP",          "Network Time Protocol",          "NEUTRO"),
    135:  ("RPC",          "MS RPC",                         "REVISAR"),
    137:  ("NetBIOS",      "NetBIOS Name",                   "REVISAR"),
    138:  ("NetBIOS",      "NetBIOS Datagram",               "REVISAR"),
    139:  ("NetBIOS-SSN",  "NetBIOS Session",                "REVISAR"),
    143:  ("IMAP",         "IMAP sin cifrar",                "INSEGURO"),
    161:  ("SNMP",         "SNMP",                           "REVISAR"),
    443:  ("HTTPS",        "Web cifrada TLS",                "SEGURO"),
    445:  ("SMB",          "Compartición de archivos",       "REVISAR"),
    465:  ("SMTPS",        "SMTP cifrado",                   "SEGURO"),
    515:  ("LPD",          "Line Printer Daemon",            "REVISAR"),
    554:  ("RTSP",         "Streaming cámaras IP",           "REVISAR"),
    587:  ("SMTP",         "SMTP submission",                "SEGURO"),
    631:  ("IPP",          "Impresión CUPS",                 "REVISAR"),
    993:  ("IMAPS",        "IMAP cifrado",                   "SEGURO"),
    995:  ("POP3S",        "POP3 cifrado",                   "SEGURO"),
    1080: ("SOCKS",        "Proxy SOCKS",                    "REVISAR"),
    1883: ("MQTT",         "MQTT IoT sin TLS",               "INSEGURO"),
    1900: ("SSDP",         "UPnP Discovery",                 "REVISAR"),
    2323: ("Telnet-alt",   "Telnet alternativo (Mirai)",     "CRITICO"),
    3306: ("MySQL",        "Base de datos MySQL",            "REVISAR"),
    3389: ("RDP",          "Escritorio remoto Windows",      "REVISAR"),
    4433: ("HTTPS-alt",    "HTTPS alternativo",              "SEGURO"),
    5000: ("UPnP",         "UPnP / Synology",                "REVISAR"),
    5353: ("mDNS",         "Multicast DNS / Bonjour",        "NEUTRO"),
    5357: ("WSDAPI",       "Web Services for Devices",       "REVISAR"),
    5683: ("CoAP",         "IoT CoAP",                       "INSEGURO"),
    5900: ("VNC",          "VNC control remoto",             "INSEGURO"),
    6667: ("IRC",          "IRC",                            "REVISAR"),
    7547: ("CWMP",         "TR-069 router",                  "CRITICO"),
    8000: ("HTTP-alt",     "HTTP alternativo",               "INSEGURO"),
    8080: ("HTTP-proxy",   "HTTP proxy / admin",             "INSEGURO"),
    8081: ("HTTP-alt",     "HTTP alternativo",               "INSEGURO"),
    8083: ("HTTP-alt",     "HTTP alternativo",               "INSEGURO"),
    8088: ("HTTP-alt",     "HTTP alternativo",               "INSEGURO"),
    8443: ("HTTPS-alt",    "HTTPS alternativo",              "SEGURO"),
    8883: ("MQTT-TLS",     "MQTT con TLS",                   "SEGURO"),
    9100: ("JetDirect",    "Impresora HP sin auth",          "REVISAR"),
    32400:("Plex",         "Servidor Plex",                  "REVISAR"),
    49152:("UPnP",         "UPnP dinámico",                  "REVISAR"),
}


# ============================================================================
#  FINGERPRINTS IoT
# ============================================================================
IOT_FINGERPRINTS = {
    "hostname": {
        "echo":         ("Amazon Echo / Alexa",     "medio"),
        "alexa":        ("Amazon Echo / Alexa",     "medio"),
        "ring":         ("Cámara/Timbre Ring",      "medio"),
        "nest":         ("Google Nest",             "medio"),
        "chromecast":   ("Google Chromecast",       "bajo"),
        "googlehome":   ("Google Home",             "medio"),
        "philips":      ("Philips Hue",             "bajo"),
        "hue":          ("Philips Hue",             "bajo"),
        "xiaomi":       ("Xiaomi IoT",              "alto"),
        "tplink":       ("TP-Link / Tapo / Kasa",   "medio"),
        "kasa":         ("TP-Link Kasa",            "medio"),
        "shelly":       ("Shelly Smart",            "medio"),
        "sonoff":       ("Sonoff IoT",              "alto"),
        "roborock":     ("Robot aspirador",         "medio"),
        "roomba":       ("iRobot Roomba",           "medio"),
        "tv":           ("Smart TV",                "medio"),
        "samsung":      ("Samsung",                 "medio"),
        "lg":           ("LG",                      "medio"),
        "printer":      ("Impresora",               "medio"),
        "hp":           ("HP (impresora?)",         "medio"),
        "canon":        ("Impresora Canon",         "medio"),
        "epson":        ("Impresora Epson",         "medio"),
        "ipcam":        ("Cámara IP",               "alto"),
        "camera":       ("Cámara IP",               "alto"),
        "doorbell":     ("Timbre inteligente",      "medio"),
        "router":       ("Router",                  "alto"),
        "gateway":      ("Router / Gateway",        "alto"),
        "homeassistant":("Home Assistant",          "bajo"),
        "hassio":       ("Home Assistant",          "bajo"),
        "raspberry":    ("Raspberry Pi",            "bajo"),
        "nas":          ("NAS",                     "alto"),
        "synology":     ("Synology NAS",            "alto"),
        "qnap":         ("QNAP NAS",                "alto"),
    },
    "oui": {
        "FC:F5:28": "Amazon",           "68:37:E9": "Amazon",
        "44:65:0D": "Amazon",           "50:DC:E7": "Amazon",
        "F0:EF:86": "Google",           "54:60:09": "Google",
        "18:B4:30": "Nest",             "64:16:66": "Nest",
        "00:17:88": "Philips Hue",      "EC:B5:FA": "Philips Hue",
        "50:EC:50": "Xiaomi",           "64:CC:2E": "Xiaomi",
        "E8:DE:27": "TP-Link",          "50:C7:BF": "TP-Link",
        "B0:BE:76": "TP-Link",          "98:DA:C4": "TP-Link",
        "DC:A6:32": "Raspberry Pi",     "B8:27:EB": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",     "28:CD:C1": "Raspberry Pi",
        "AC:BC:32": "Apple",            "A4:83:E7": "Apple",
        "F0:D7:AA": "Apple",            "3C:22:FB": "Apple",
        "00:11:32": "Synology",
        "24:0A:C4": "Espressif (ESP)",  "A0:20:A6": "Espressif (ESP)",
        "7C:9E:BD": "Espressif (ESP)",  "AC:67:B2": "Espressif (ESP)",
    }
}


# ============================================================================
#  MAPEO PARA CPE (CVE lookup)
# ============================================================================
# Traduce nombres de producto detectados por banner/fingerprint a
# identificadores CPE 2.3 que entiende la NVD API.
# Formato CPE: cpe:2.3:{part}:{vendor}:{product}:{version}
# part = a(pplication) | o(perating_system) | h(ardware)
CPE_MAPPINGS: Dict[str, Tuple[str, str, str]] = {
    # producto en minúsculas : (part, vendor, product)
    "apache":           ("a", "apache",        "http_server"),
    "apache httpd":     ("a", "apache",        "http_server"),
    "nginx":            ("a", "nginx",         "nginx"),
    "openssh":          ("a", "openbsd",       "openssh"),
    "microsoft-iis":    ("a", "microsoft",     "internet_information_services"),
    "iis":              ("a", "microsoft",     "internet_information_services"),
    "lighttpd":         ("a", "lighttpd",      "lighttpd"),
    "boa":              ("a", "boa",           "boa"),
    "gsoap":            ("a", "genivia",       "gsoap"),
    "rompager":         ("a", "allegro",       "rompager"),
    "dropbear":         ("a", "dropbear_ssh_project", "dropbear_ssh"),
    "thttpd":           ("a", "acme",          "thttpd"),
    "mosquitto":        ("a", "eclipse",       "mosquitto"),
    "proftpd":          ("a", "proftpd",       "proftpd"),
    "vsftpd":           ("a", "vsftpd_project","vsftpd"),
    "mysql":            ("a", "oracle",        "mysql"),
    "mariadb":          ("a", "mariadb",       "mariadb"),
    "samba":            ("a", "samba",         "samba"),
    "cups":             ("a", "apple",         "cups"),
    "postfix":          ("a", "postfix",       "postfix"),
    "exim":             ("a", "exim",          "exim"),
    "bind":             ("a", "isc",           "bind"),
    "dnsmasq":          ("a", "thekelleys",    "dnsmasq"),
}


# ============================================================================
#  UMBRALES DE SCORING
# ============================================================================
@dataclass
class RiskThresholds:
    """Umbrales para clasificar el riesgo de un dispositivo."""
    critico: int = 60
    alto:    int = 35
    medio:   int = 15
    # por debajo de medio → BAJO, cero → MÍNIMO

    # Puntos por severidad de un hallazgo
    points_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "CRITICA": 30,
        "ALTA":    15,
        "MEDIA":   7,
        "BAJA":    2,
    })

    # Puntos adicionales por CVE encontrado (según CVSS)
    points_by_cvss: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 25,  # CVSS 9.0-10.0
        "HIGH":     15,  # CVSS 7.0-8.9
        "MEDIUM":   7,   # CVSS 4.0-6.9
        "LOW":      2,   # CVSS 0.1-3.9
        "NONE":     0,
    })

RISK = RiskThresholds()


# ============================================================================
#  PERFILES DE ESCANEO
# ============================================================================
SCAN_PROFILES = {
    "fast": {
        "ports": [21, 22, 23, 80, 443, 445, 554, 1883, 8080, 8443],
        "timeout": 0.5,
        "description": "Escaneo rápido (puertos críticos)",
    },
    "standard": {
        "ports": list(COMMON_PORTS.keys()),
        "timeout": 1.0,
        "description": "Escaneo estándar (50 puertos típicos)",
    },
    "full": {
        "ports": list(range(1, 1025)) + [1883, 1900, 2323, 3306, 3389,
                  5000, 5353, 5683, 5900, 8000, 8080, 8081, 8083, 8088,
                  8443, 8883, 9100, 32400, 49152],
        "timeout": 1.0,
        "description": "Escaneo completo (top 1000 + IoT)",
    },
}
