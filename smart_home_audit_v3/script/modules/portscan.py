"""
===============================================================================
 modules/portscan.py
 -----------------------------------------------------------------------------
 Escaneo de puertos TCP + Banner Grabbing + Parseo de versión.

 Para cada puerto abierto intentamos extraer:
   - El servicio (HTTP, SSH, SMB...)
   - El producto (Apache, OpenSSH, nginx...)
   - La versión (2.4.41, 8.2p1...)
   - El CPE (identificador estándar CPE 2.3)

 El CPE es clave porque es lo que enviaremos al módulo CVE para buscar
 vulnerabilidades conocidas en la NVD.
===============================================================================
"""
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional

from core import (COMMON_PORTS, CPE_MAPPINGS, Service, Finding,
                  get_progress, console)
from core.config import (DEFAULT_PORT_TIMEOUT, BANNER_TIMEOUT,
                          PORT_SCAN_WORKERS)


# ============================================================================
#  ESCANEO DE PUERTOS (TCP Connect)
# ============================================================================
def scan_port(ip: str, port: int, timeout: float = DEFAULT_PORT_TIMEOUT) -> bool:
    """Comprueba si un puerto TCP está abierto. True si lo está."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((ip, port))
        s.close()
        return res == 0
    except Exception:
        return False


def scan_host_ports(ip: str, ports: List[int],
                    timeout: float = DEFAULT_PORT_TIMEOUT) -> List[int]:
    """Escanea en paralelo una lista de puertos en un host."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])
    return sorted(open_ports)


# ============================================================================
#  BANNER GRABBING
# ============================================================================
def grab_banner(ip: str, port: int, timeout: float = BANNER_TIMEOUT) -> str:
    """Obtiene el banner del servicio en ese puerto."""
    # Puertos TLS: handshake
    if port in (443, 8443, 4433, 8883, 993, 995, 465):
        return _grab_tls(ip, port, timeout)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # En HTTP hay que pedir para obtener respuesta
        if port in (80, 8080, 8000, 8081, 8088, 8083, 5000, 7547):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() +
                      b"\r\nUser-Agent: SmartHomeAudit/2.0\r\n\r\n")

        data = s.recv(2048)
        s.close()

        banner = data.decode("utf-8", errors="replace").strip()
        return _clean_banner(banner)
    except Exception:
        return ""


def _grab_tls(ip: str, port: int, timeout: float) -> str:
    """Extrae info del handshake TLS: versión, cert CN, issuer."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ss:
                version = ss.version() or "TLS?"
                cipher = ss.cipher()
                cipher_str = cipher[0] if cipher else "?"
                cert = ss.getpeercert(binary_form=False)
                cn, issuer = "", ""
                if cert:
                    for t in cert.get("subject", ()):
                        for k, v in t:
                            if k == "commonName":
                                cn = v
                    for t in cert.get("issuer", ()):
                        for k, v in t:
                            if k == "commonName":
                                issuer = v
                return f"{version} | {cipher_str} | CN={cn or '-'} | Issuer={issuer or '-'}"
    except Exception as e:
        return f"TLS handshake failed ({type(e).__name__})"


def _clean_banner(banner: str) -> str:
    """Extrae las líneas útiles de un banner, principalmente 'Server:'."""
    if not banner:
        return ""
    lines = banner.splitlines()
    # Busca la línea Server: si es HTTP
    for line in lines:
        if line.lower().startswith("server:"):
            return line.strip()[:250]
    # si no, la primera línea no vacía
    for line in lines:
        if line.strip():
            return line.strip()[:250]
    return banner[:250]


# ============================================================================
#  PARSING: Banner → (producto, versión, CPE)
# ============================================================================

# Patrones regex para extraer producto+versión de banners habituales
BANNER_PATTERNS = [
    # SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    (re.compile(r"SSH-[\d.]+-(\w+)[_\s/-]+([\d.p]+)", re.I),
     lambda m: (m.group(1).lower(), m.group(2))),
    # HTTP Server: "Server: Apache/2.4.41 (Ubuntu)"
    (re.compile(r"(?:Server:\s*)?([A-Za-z][\w-]*)[/\s]+([\d.]+[\w.-]*)", re.I),
     lambda m: (m.group(1).lower(), m.group(2))),
    # FTP: "220 ProFTPD 1.3.5e Server ready"
    (re.compile(r"(ProFTPD|vsftpd|FileZilla|Pure-FTPd)[\s/]+([\d.]+[\w.-]*)", re.I),
     lambda m: (m.group(1).lower(), m.group(2))),
    # SMTP: "220 mail.example.com ESMTP Postfix (Ubuntu)"
    (re.compile(r"ESMTP\s+(\w+)", re.I),
     lambda m: (m.group(1).lower(), "")),
    # MySQL: "5.7.42-0ubuntu0.18.04.1"
    (re.compile(r"^([\d]+\.[\d]+\.[\d]+)[-\w.]*$"),
     lambda m: ("mysql", m.group(1))),
]


def parse_banner(banner: str) -> Tuple[str, str]:
    """
    Extrae (producto, versión) de un banner.
    Devuelve ('', '') si no consigue parsearlo.
    """
    if not banner:
        return "", ""
    for pattern, extract in BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            try:
                product, version = extract(m)
                # Filtramos falsos positivos típicos
                if product in ("http", "https", "server", "x-powered-by"):
                    continue
                return product, version
            except Exception:
                continue
    return "", ""


def build_cpe(product: str, version: str = "") -> str:
    """
    Construye un CPE 2.3 a partir del producto detectado.
    Formato: cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*
    """
    if not product:
        return ""
    key = product.lower().strip()
    if key not in CPE_MAPPINGS:
        return ""
    part, vendor, product_name = CPE_MAPPINGS[key]
    version_field = version.strip() if version else "*"
    return f"cpe:2.3:{part}:{vendor}:{product_name}:{version_field}:*:*:*:*:*:*:*"


# ============================================================================
#  ANÁLISIS DE SEGURIDAD DEL PUERTO/SERVICIO
# ============================================================================

# Patrones de software obsoleto/vulnerable en banners
VULNERABLE_BANNER_PATTERNS = [
    (re.compile(r"Apache[/\s]+(1\.|2\.0|2\.2)", re.I),
     "ALTA", "Apache HTTP Server en versión muy antigua, sin soporte."),
    (re.compile(r"nginx[/\s]+0\.", re.I),
     "ALTA", "nginx en versión obsoleta (0.x)."),
    (re.compile(r"OpenSSH[_\s]+([45])\.", re.I),
     "MEDIA", "OpenSSH en versión 4.x/5.x, revisa CVEs aplicables."),
    (re.compile(r"OpenSSH[_\s]+6\.", re.I),
     "MEDIA", "OpenSSH 6.x con posibles CVEs conocidos."),
    (re.compile(r"Microsoft-IIS[/\s]+[567]\.", re.I),
     "CRITICA", "Servidor Microsoft IIS sin soporte (6.0/7.0)."),
    (re.compile(r"Boa[/\s]", re.I),
     "CRITICA", "Servidor 'Boa': típico en cámaras IP baratas con múltiples CVEs."),
    (re.compile(r"gSOAP", re.I),
     "ALTA", "gSOAP usado en cámaras IP — histórico de CVEs críticos."),
    (re.compile(r"RomPager", re.I),
     "CRITICA", "RomPager: vulnerable a 'Misfortune Cookie' (CVE-2014-9222)."),
    (re.compile(r"lighttpd[/\s]+1\.4\.[0-9]\D", re.I),
     "MEDIA", "lighttpd 1.4.x antiguo, común en firmwares de router vulnerables."),
    (re.compile(r"thttpd[/\s]+2\.2[0-5]", re.I),
     "MEDIA", "thttpd en versión con CVEs conocidos."),
    (re.compile(r"\bTLSv?1\.?0\b|\bSSLv[23]\b", re.I),
     "ALTA", "Versión TLS/SSL obsoleta (TLS 1.0 o SSLv2/3). Solo debe aceptarse TLS 1.2+."),
    (re.compile(r"\bTLSv?1\.?1\b", re.I),
     "MEDIA", "TLS 1.1 obsoleto, actualiza a TLS 1.2 o 1.3."),
]


def analyze_service(service: Service) -> List[Finding]:
    """Genera hallazgos (Finding) sobre un servicio a partir de su banner y clasificación."""
    findings = []

    # Hallazgo por clasificación del puerto
    cls = service.classification
    port = service.port
    name = service.name

    if cls == "CRITICO":
        findings.append(Finding(
            severity="CRITICA",
            category="port",
            title=f"Puerto {port}/{name} con protocolo crítico",
            description=f"El servicio {name} en el puerto {port} usa un "
                        f"protocolo muy inseguro y ha sido explotado "
                        f"históricamente por malware (Mirai, etc.).",
            recommendation="Deshabilitar el servicio o sustituirlo por una "
                           "alternativa cifrada."
        ))
    elif cls == "INSEGURO":
        findings.append(Finding(
            severity="ALTA",
            category="port",
            title=f"Puerto {port}/{name} transmite sin cifrar",
            description=f"{name} envía información en claro por la red. "
                        f"Puede ser interceptado con sniffing.",
            recommendation="Usar la variante cifrada equivalente (HTTPS, "
                           "SFTP, IMAPS, SMTPS, MQTT-TLS...)."
        ))
    elif cls == "REVISAR":
        findings.append(Finding(
            severity="MEDIA",
            category="port",
            title=f"Puerto {port}/{name} expuesto",
            description=f"{name} debe auditarse: su exposición puede "
                        f"revelar información del sistema o permitir ataques "
                        f"si no está bien configurado.",
            recommendation="Restringir el acceso por firewall/red interna "
                           "si no se usa desde fuera."
        ))

    # Hallazgos por banner
    banner = service.banner
    if banner:
        for pattern, severity, message in VULNERABLE_BANNER_PATTERNS:
            if pattern.search(banner):
                findings.append(Finding(
                    severity=severity,
                    category="version",
                    title="Versión de software potencialmente vulnerable",
                    description=message + f" Banner detectado: '{banner[:100]}'",
                    recommendation="Actualizar a la última versión estable "
                                   "del fabricante."
                ))
                break  # un hallazgo por banner basta

    return findings


# ============================================================================
#  FUNCIÓN PRINCIPAL
# ============================================================================
def scan_services(ip: str, ports: List[int],
                  timeout: float = DEFAULT_PORT_TIMEOUT) -> dict[int, Service]:
    """
    Escanea los puertos, hace banner grabbing y devuelve Services completos.
    """
    services: dict[int, Service] = {}
    open_ports = scan_host_ports(ip, ports, timeout)

    for port in open_ports:
        info = COMMON_PORTS.get(port, (f"port-{port}", "", "REVISAR"))
        banner = grab_banner(ip, port)
        product, version = parse_banner(banner)
        cpe = build_cpe(product, version) if product else ""

        service = Service(
            port=port,
            name=info[0],
            banner=banner,
            product=product,
            version=version,
            cpe=cpe,
            classification=info[2],
        )
        services[port] = service

    return services
