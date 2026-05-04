"""
===============================================================================
 modules/scoring.py
 -----------------------------------------------------------------------------
 Sistema de puntuación de riesgo por dispositivo y a nivel global.

 METODOLOGÍA DE SCORING (para la memoria):
 ----------------------------------------
 1. Cada hallazgo (Finding) aporta puntos según su severidad.
 2. Cada CVE encontrado aporta puntos según CVSS.
 3. El número total de puertos abiertos añade un pequeño penalizador
    (superficie de ataque).
 4. El tipo de dispositivo actúa como multiplicador:
      - router/NAS/cámara IP (alto): ×1.3
      - Smart TV, altavoz, impresora (medio): ×1.0
      - bombilla, Chromecast (bajo): ×0.7
 5. Los CVEs del catálogo CISA KEV (explotados activamente) se
    penalizan extra porque son prioridad absoluta.
===============================================================================
"""
from typing import List, Dict
from core import Device, Finding, RISK


def calculate_device_score(device: Device) -> int:
    """Calcula el score de riesgo (0-100) de un dispositivo."""
    score = 0.0

    # 1. Puntos por hallazgos
    for f in device.findings:
        score += RISK.points_by_severity.get(f.severity, 1)

    # 2. Puntos por CVEs (los Finding CVE ya se contaron arriba, pero los
    #    que no pasen a Finding los contamos aquí también, con peso menor)
    for service in device.services.values():
        for cve in service.cves:
            # Solo contar los que no están como Finding
            # (Críticos y Altos ya están como finding)
            if cve.cvss_severity in ("MEDIUM", "LOW"):
                score += RISK.points_by_cvss.get(cve.cvss_severity, 0) * 0.5
            # Extra si está en KEV
            if cve.in_kev:
                score += 10

    # 3. Superficie de ataque (nº de puertos)
    score += min(len(device.open_ports) * 1.5, 15)

    # 4. Multiplicador por tipo
    multiplier = {"alto": 1.3, "medio": 1.0, "bajo": 0.7}.get(
        device.type_risk, 1.0)
    score *= multiplier

    return min(int(round(score)), 100)


def risk_level_from_score(score: int) -> str:
    """Convierte score numérico a etiqueta."""
    if score >= RISK.critico:  return "CRÍTICO"
    if score >= RISK.alto:     return "ALTO"
    if score >= RISK.medio:    return "MEDIO"
    if score > 0:              return "BAJO"
    return "MÍNIMO"


def apply_scoring(devices: List[Device]) -> None:
    """Calcula y asigna risk_score + risk_level a todos los dispositivos."""
    for device in devices:
        device.risk_score = calculate_device_score(device)
        device.risk_level = risk_level_from_score(device.risk_score)


def build_conclusions(devices: List[Device], meta) -> dict:
    """
    Genera el diccionario de conclusiones globales.
    """
    total = len(devices)
    by_level = {"CRÍTICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "MÍNIMO": 0}
    for d in devices:
        by_level[d.risk_level] = by_level.get(d.risk_level, 0) + 1

    # Agregados de protocolos
    n_telnet = sum(1 for d in devices
                   if any(p in d.open_ports for p in (23, 2323)))
    n_ftp = sum(1 for d in devices if 21 in d.open_ports)
    n_http = sum(1 for d in devices
                 if any(p in d.open_ports for p in (80, 8080, 8000, 8081, 8088)))
    n_smb = sum(1 for d in devices
                if any(p in d.open_ports for p in (139, 445)))
    n_upnp = sum(1 for d in devices
                 if any(p in d.open_ports for p in (1900, 5000, 49152)))
    n_cleartext = sum(1 for d in devices
                      if any(p in d.open_ports
                             for p in (21, 23, 80, 110, 143, 1883, 5900)))

    # Estadísticas CVE
    total_cves = sum(d.total_cves for d in devices)
    critical_cves = sum(d.critical_cves for d in devices)
    kev_cves = sum(1 for d in devices
                   for s in d.services.values()
                   for c in s.cves if c.in_kev)

    # Dispositivos críticos/altos
    score_avg = sum(d.risk_score for d in devices) / total if total else 0

    if score_avg >= 50:
        global_risk = "CRÍTICO"
    elif score_avg >= 30:
        global_risk = "ALTO"
    elif score_avg >= 15:
        global_risk = "MEDIO"
    else:
        global_risk = "BAJO"

    # Top 5 dispositivos más expuestos
    top_risk = sorted(devices, key=lambda d: -d.risk_score)[:5]

    conclusions = {
        "resumen": {
            "total_dispositivos": total,
            "por_nivel": by_level,
            "score_medio": round(score_avg, 1),
            "riesgo_global": global_risk,
        },
        "cve_resumen": {
            "total_cves": total_cves,
            "cves_criticos": critical_cves,
            "cves_en_kev": kev_cves,  # Known Exploited Vulnerabilities
        },
        "protocolos_inseguros": {
            "telnet": n_telnet,
            "ftp": n_ftp,
            "http_sin_tls": n_http,
            "smb_netbios": n_smb,
            "upnp": n_upnp,
            "cleartext_total": n_cleartext,
        },
        "top_riesgo": [
            {"ip": d.ip, "tipo": d.device_type,
             "score": d.risk_score, "nivel": d.risk_level,
             "cves": d.total_cves, "cves_criticos": d.critical_cves}
            for d in top_risk
        ],
        "recomendaciones": generate_recommendations(
            devices, n_telnet, n_ftp, n_http, n_smb, n_upnp,
            critical_cves, kev_cves),
    }
    return conclusions


def generate_recommendations(devices, n_telnet, n_ftp, n_http,
                              n_smb, n_upnp, critical_cves,
                              kev_cves) -> List[str]:
    """Genera recomendaciones priorizadas y accionables."""
    recs = []

    # Priorizar KEV (crítico de verdad)
    if kev_cves:
        recs.append(f"[PRIORIDAD MÁXIMA] Se han detectado {kev_cves} CVEs "
                    f"del catálogo CISA KEV (Known Exploited Vulnerabilities). "
                    f"Estas vulnerabilidades SE ESTÁN EXPLOTANDO ACTIVAMENTE "
                    f"en el mundo real. Actualizar los dispositivos afectados "
                    f"de forma inmediata.")

    if critical_cves:
        recs.append(f"Se han identificado {critical_cves} vulnerabilidades "
                    f"de severidad CRÍTICA (CVSS 9.0+). Revisar los "
                    f"dispositivos afectados y aplicar los parches del "
                    f"fabricante o sustituir el equipo si ya no tiene soporte.")

    if n_telnet:
        recs.append("Deshabilitar Telnet (puertos 23/2323) en TODOS los "
                    "dispositivos. Es el vector principal usado por botnets "
                    "como Mirai para comprometer IoT.")

    if n_ftp:
        recs.append("Sustituir FTP (21) por SFTP/FTPS o desactivarlo. "
                    "FTP transmite credenciales en texto plano.")

    if n_http:
        recs.append("Los paneles de administración por HTTP plano son "
                    "interceptables. Forzar HTTPS o restringir el acceso "
                    "a la red interna.")

    if n_smb:
        recs.append("Revisar SMB/NetBIOS (139/445): actualizar a SMBv3, "
                    "deshabilitar SMBv1 (vulnerable a EternalBlue) y no "
                    "exponer estos puertos a internet.")

    if n_upnp:
        recs.append("Desactivar UPnP en el router: puede abrir puertos "
                    "automáticamente sin consentimiento, es un vector "
                    "conocido de ataque en redes domésticas.")

    # Cámaras detectadas
    n_cameras = sum(1 for d in devices
                    if "cámara" in d.device_type.lower() or
                       "camera" in d.device_type.lower())
    if n_cameras:
        recs.append(f"Se han detectado {n_cameras} posibles cámaras IP: "
                    f"cambiar contraseñas por defecto, actualizar firmware "
                    f"y segregarlas en una VLAN o red de invitados.")

    # Recomendaciones genéricas (siempre)
    recs.extend([
        "Mantener el firmware del router y de todos los dispositivos IoT "
        "actualizado periódicamente.",
        "Separar la red IoT de la red principal mediante SSID de invitados "
        "o una VLAN dedicada.",
        "Desactivar servicios y cuentas no utilizadas en cada dispositivo.",
        "Usar WPA3 (o como mínimo WPA2-AES) con contraseñas robustas de "
        "más de 16 caracteres.",
        "Cambiar credenciales por defecto en TODOS los dispositivos: "
        "routers, cámaras, NAS, impresoras, asistentes de voz.",
        "Activar el cortafuegos del router y bloquear tráfico entrante "
        "no solicitado.",
        "Establecer una política de auditorías periódicas (ejecutar esta "
        "herramienta mensualmente).",
        "Revisar los permisos y políticas de privacidad de las apps "
        "móviles asociadas a cada dispositivo IoT.",
    ])
    return recs
