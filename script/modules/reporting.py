"""
===============================================================================
 modules/reporting.py  (v4 - estilo discreto)
 -----------------------------------------------------------------------------
 Generación de informes en JSON / TXT / HTML.

 Diseño HTML:
   Paleta sobria (azules apagados, sin neón, sin brillos)
   Tipografía: sans-serif limpia, mono solo en código
   Sin animaciones llamativas (solo transiciones suaves de hover)
   Tabla de inventario reestructurada: puertos en lista vertical legible
===============================================================================
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Tuple


# ============================================================================
#  ENTRY POINT
# ============================================================================
def save_all_reports(report, outdir: Path = None) -> Tuple[Path, Path, Path]:
    data = _to_dict(report)

    if outdir is None:
        outdir = Path(__file__).resolve().parent.parent / "reports"
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = outdir / f"audit_{ts}.json"
    txt_path  = outdir / f"audit_{ts}.txt"
    html_path = outdir / f"audit_{ts}.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(_build_txt(data))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html(data))

    return json_path, txt_path, html_path


# ============================================================================
#  Conversión flexible a dict
# ============================================================================
def _to_dict(report) -> dict:
    if isinstance(report, dict):
        return report
    if hasattr(report, "to_dict"):
        return report.to_dict()
    out = {}
    for attr in ("meta", "metadata", "summary", "conclusions"):
        if hasattr(report, attr):
            out[attr] = _obj_to_dict(getattr(report, attr))
    if hasattr(report, "devices"):
        out["devices"] = [_obj_to_dict(d) for d in report.devices]
    return out


def _obj_to_dict(obj):
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _obj_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_obj_to_dict(x) for x in obj]
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__"):
        return {k: _obj_to_dict(v) for k, v in obj.__dict__.items()
                if not k.startswith("_")}
    return str(obj)


# ============================================================================
#  Helpers de extracción
# ============================================================================
def _get_meta(data: dict) -> dict:
    return data.get("meta") or data.get("metadata") or {}

def _get_devices(data: dict) -> list:
    return data.get("devices", []) or []

def _get_conclusions(data: dict) -> dict:
    c = data.get("conclusions") or data.get("summary") or {}
    if not c:
        c = _build_conclusions_from_devices(_get_devices(data))
    return c


def _build_conclusions_from_devices(devices: list) -> dict:
    """Genera el dict de conclusiones si el script no lo provee."""
    total = len(devices)
    by_level = {"CRÍTICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "MÍNIMO": 0}
    score_sum = 0
    total_cves = 0
    critical_cves = 0
    high_cves = 0

    # Listas de IPs por protocolo inseguro (para recomendaciones específicas)
    ips_telnet, ips_ftp, ips_http, ips_smb, ips_upnp, ips_vnc = [], [], [], [], [], []
    ips_with_critical_cve = []
    ips_with_kev = []
    ips_camera, ips_router = [], []

    for d in devices:
        ip = d.get("ip", "?")
        lvl = d.get("risk_level", "MÍNIMO")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        score_sum += d.get("risk_score", 0)

        ports_int = []
        ports_src = d.get("open_ports", []) or list((d.get("services", {}) or {}).keys())
        for p in ports_src:
            try:
                ports_int.append(int(p))
            except (ValueError, TypeError):
                pass

        if any(p in ports_int for p in (23, 2323)): ips_telnet.append(ip)
        if 21 in ports_int: ips_ftp.append(ip)
        if any(p in ports_int for p in (80, 8080, 8000, 8081, 8088)): ips_http.append(ip)
        if any(p in ports_int for p in (139, 445)): ips_smb.append(ip)
        if any(p in ports_int for p in (1900, 5000, 49152)): ips_upnp.append(ip)
        if 5900 in ports_int: ips_vnc.append(ip)

        # Tipo
        dt = (d.get("device_type", "") or "").lower()
        if "cámara" in dt or "camera" in dt: ips_camera.append(ip)
        if "router" in dt or "gateway" in dt: ips_router.append(ip)

        services = d.get("services", {}) or {}
        if isinstance(services, dict):
            had_crit = had_kev = False
            for s in services.values():
                cves = s.get("cves", []) if isinstance(s, dict) else []
                total_cves += len(cves)
                for cv in cves:
                    if not isinstance(cv, dict):
                        continue
                    sev = (cv.get("cvss_severity", "") or "").upper()
                    if sev == "CRITICAL":
                        critical_cves += 1
                        had_crit = True
                    elif sev == "HIGH":
                        high_cves += 1
                    if cv.get("in_kev"):
                        had_kev = True
            if had_crit: ips_with_critical_cve.append(ip)
            if had_kev: ips_with_kev.append(ip)

    avg = score_sum / total if total else 0
    if avg >= 50: global_risk = "CRÍTICO"
    elif avg >= 30: global_risk = "ALTO"
    elif avg >= 15: global_risk = "MEDIO"
    else: global_risk = "BAJO"

    return {
        "resumen": {
            "total_dispositivos": total,
            "por_nivel": by_level,
            "score_medio": round(avg, 1),
            "riesgo_global": global_risk,
        },
        "cve_resumen": {
            "total_cves": total_cves,
            "cves_criticos": critical_cves,
            "cves_altos": high_cves,
            "cves_en_kev": len(ips_with_kev),
        },
        "protocolos_inseguros": {
            "telnet": len(ips_telnet),
            "ftp": len(ips_ftp),
            "http_sin_tls": len(ips_http),
            "smb_netbios": len(ips_smb),
            "upnp": len(ips_upnp),
        },
        "top_riesgo": [
            {"ip": d.get("ip", "?"),
             "tipo": d.get("device_type", "Desconocido"),
             "score": d.get("risk_score", 0),
             "nivel": d.get("risk_level", "MÍNIMO"),
             "cves": _count_cves(d),
             "cves_criticos": _count_critical_cves(d)}
            for d in sorted(devices, key=lambda x: -x.get("risk_score", 0))[:5]
            if d.get("risk_score", 0) > 0
        ],
        "recomendaciones": _generate_recommendations(
            ips_telnet, ips_ftp, ips_http, ips_smb, ips_upnp, ips_vnc,
            ips_with_critical_cve, ips_with_kev, ips_camera, ips_router),
    }


def _count_cves(device: dict) -> int:
    services = device.get("services", {}) or {}
    if isinstance(services, dict):
        return sum(len(s.get("cves", []) if isinstance(s, dict) else [])
                   for s in services.values())
    return 0


def _count_critical_cves(device: dict) -> int:
    services = device.get("services", {}) or {}
    n = 0
    if isinstance(services, dict):
        for s in services.values():
            if isinstance(s, dict):
                for c in s.get("cves", []) or []:
                    if isinstance(c, dict) and c.get("cvss_severity", "").upper() == "CRITICAL":
                        n += 1
    return n


# ============================================================================
#  RECOMENDACIONES PERSONALIZADAS
# ============================================================================
def _generate_recommendations(ips_telnet, ips_ftp, ips_http, ips_smb,
                               ips_upnp, ips_vnc, ips_with_critical_cve,
                               ips_with_kev, ips_camera, ips_router) -> list:
    """
    Genera recomendaciones específicas mencionando IPs reales detectadas.
    Si no se detecta un problema, NO aparece la recomendación correspondiente.
    """
    recs = []

    # ---- PRIORIDAD MÁXIMA: KEV (explotados activamente) ----
    if ips_with_kev:
        ips_str = ", ".join(ips_with_kev[:5])
        if len(ips_with_kev) > 5:
            ips_str += f" y {len(ips_with_kev) - 5} más"
        recs.append({
            "priority": "URGENTE",
            "title": "Vulnerabilidades explotadas activamente (CISA KEV)",
            "description": f"Los siguientes dispositivos tienen CVEs del catálogo "
                           f"CISA KEV (Known Exploited Vulnerabilities), que SE ESTÁN "
                           f"EXPLOTANDO en este momento en internet: {ips_str}. "
                           f"Aplicar parches del fabricante INMEDIATAMENTE o, si el "
                           f"dispositivo ya no tiene soporte, sustituirlo.",
        })

    # ---- CRÍTICOS ----
    if ips_with_critical_cve:
        ips_str = ", ".join(ips_with_critical_cve[:5])
        if len(ips_with_critical_cve) > 5:
            ips_str += f" y {len(ips_with_critical_cve) - 5} más"
        recs.append({
            "priority": "ALTA",
            "title": "Vulnerabilidades críticas (CVSS ≥ 9.0)",
            "description": f"Dispositivos con CVEs de severidad CRÍTICA detectados: "
                           f"{ips_str}. Revisar el detalle de cada CVE en la sección "
                           f"de inventario y aplicar las actualizaciones disponibles.",
        })

    # ---- TELNET ----
    if ips_telnet:
        ips_str = ", ".join(ips_telnet)
        recs.append({
            "priority": "ALTA",
            "title": "Telnet expuesto",
            "description": f"Telnet (puertos 23/2323) detectado en: {ips_str}. "
                           f"Es el protocolo principal usado por la botnet Mirai "
                           f"para comprometer IoT. Deshabilitar Telnet en estos "
                           f"dispositivos y, si se necesita acceso remoto, usar SSH.",
        })

    # ---- FTP ----
    if ips_ftp:
        ips_str = ", ".join(ips_ftp)
        recs.append({
            "priority": "ALTA",
            "title": "FTP transmite credenciales en claro",
            "description": f"FTP (puerto 21) detectado en: {ips_str}. Este protocolo "
                           f"envía usuario y contraseña sin cifrar, interceptables con "
                           f"cualquier sniffer en la red. Sustituir por SFTP o FTPS, "
                           f"o desactivar el servicio si no se usa.",
        })

    # ---- VNC ----
    if ips_vnc:
        ips_str = ", ".join(ips_vnc)
        recs.append({
            "priority": "ALTA",
            "title": "VNC sin cifrado expuesto",
            "description": f"VNC (puerto 5900) detectado en: {ips_str}. Las versiones "
                           f"clásicas de VNC envían el escritorio sin cifrar y a menudo "
                           f"sin contraseña robusta. Usar TigerVNC con TLS, túnel SSH, "
                           f"o protocolos modernos como NoMachine.",
        })

    # ---- HTTP sin TLS ----
    if ips_http:
        if len(ips_http) <= 5:
            ips_str = ", ".join(ips_http)
            text = (f"HTTP plano detectado en: {ips_str}. ")
        else:
            text = (f"HTTP plano detectado en {len(ips_http)} dispositivos. ")
        recs.append({
            "priority": "MEDIA",
            "title": "Paneles de administración sin cifrar",
            "description": text +
                           "Las credenciales viajan en claro y pueden ser "
                           "capturadas. Forzar HTTPS en los paneles de admin o "
                           "restringir el acceso únicamente a la red local "
                           "interna mediante reglas de firewall.",
        })

    # ---- SMB / NetBIOS ----
    if ips_smb:
        ips_str = ", ".join(ips_smb)
        recs.append({
            "priority": "MEDIA",
            "title": "SMB / NetBIOS expuesto",
            "description": f"SMB/NetBIOS (139/445) detectado en: {ips_str}. "
                           f"Asegurarse de que SMBv1 está deshabilitado (vulnerable "
                           f"a EternalBlue/WannaCry) y de que estos puertos no están "
                           f"expuestos a internet a través del router.",
        })

    # ---- UPnP ----
    if ips_upnp:
        ips_str = ", ".join(ips_upnp)
        recs.append({
            "priority": "MEDIA",
            "title": "UPnP activo",
            "description": f"UPnP detectado en: {ips_str}. UPnP permite a aplicaciones "
                           f"abrir puertos automáticamente en el router sin pedir "
                           f"permiso al usuario, vector frecuente de ataques. "
                           f"Desactivarlo en la configuración del router salvo que "
                           f"sea estrictamente necesario.",
        })

    # ---- Cámaras ----
    if ips_camera:
        ips_str = ", ".join(ips_camera)
        recs.append({
            "priority": "MEDIA",
            "title": f"{len(ips_camera)} cámara(s) IP detectada(s)",
            "description": f"Cámaras detectadas en: {ips_str}. Las cámaras IP son uno "
                           f"de los dispositivos más comprometidos en redes domésticas. "
                           f"Cambiar las contraseñas por defecto, mantener el firmware "
                           f"actualizado y aislarlas en una VLAN o red de invitados "
                           f"separada del resto de la red.",
        })

    # ---- Router ----
    if ips_router:
        ips_str = ", ".join(ips_router)
        recs.append({
            "priority": "MEDIA",
            "title": "Router doméstico detectado",
            "description": f"Router en {ips_str}. Comprobar que el firmware está "
                           f"actualizado, que el panel de administración no es "
                           f"accesible desde la WAN, y que las credenciales del admin "
                           f"se han cambiado de los valores por defecto.",
        })

    # ---- Recomendaciones genéricas (siempre al final, baja prioridad) ----
    recs.extend([
        {
            "priority": "BAJA",
            "title": "Actualizar firmware periódicamente",
            "description": "Establecer una rutina mensual de revisión de "
                           "actualizaciones de firmware en router y dispositivos IoT.",
        },
        {
            "priority": "BAJA",
            "title": "Segregar red IoT",
            "description": "Crear un SSID de invitados o una VLAN dedicada para los "
                           "dispositivos IoT, separándolos de ordenadores y móviles "
                           "personales para limitar el impacto de un compromiso.",
        },
        {
            "priority": "BAJA",
            "title": "Reforzar la red Wi-Fi",
            "description": "Usar WPA3 (o como mínimo WPA2-AES) con contraseña de al "
                           "menos 16 caracteres aleatorios. Desactivar WPS.",
        },
        {
            "priority": "BAJA",
            "title": "Auditorías recurrentes",
            "description": "Ejecutar esta auditoría mensualmente y comparar los "
                           "resultados con auditorías anteriores para detectar "
                           "dispositivos nuevos o cambios sospechosos.",
        },
    ])
    return recs


# ============================================================================
#  TXT
# ============================================================================
def _build_txt(data: dict) -> str:
    m = _get_meta(data)
    devices = _get_devices(data)
    c = _get_conclusions(data)
    r = c.get("resumen", c.get("summary", {}))
    cve = c.get("cve_resumen", {})
    prot = c.get("protocolos_inseguros", {})

    lines = []
    add = lines.append
    add("=" * 78)
    add("  SMART HOME SECURITY AUDIT — INFORME TÉCNICO")
    add("=" * 78)
    add("")
    add(f"  Fecha         : {m.get('timestamp', '?')}")
    add(f"  Red auditada  : {m.get('network', '?')}")
    add(f"  Interfaz      : {m.get('interface', '-')}")
    add(f"  Gateway       : {m.get('gateway', '-')}")
    if m.get("public_ip"):
        add(f"  IP pública    : {m['public_ip']}")
    add(f"  Duración      : {m.get('duration', 0):.1f}s")
    add(f"  Modo          : {m.get('mode', '-')}")
    add(f"  Puertos/host  : {m.get('ports_scanned', '-')}")
    add("")
    add("-" * 78)
    add("  RESUMEN EJECUTIVO")
    add("-" * 78)
    add("")
    add(f"  Riesgo global ........... {r.get('riesgo_global', r.get('global_risk', '?'))}")
    add(f"  Score medio ............. {r.get('score_medio', r.get('avg_score', 0))}/100")
    add(f"  Dispositivos totales .... {r.get('total_dispositivos', r.get('total_devices', 0))}")
    add("")
    by = r.get("por_nivel", r.get("by_risk", {}))
    for nivel in ("CRÍTICO", "ALTO", "MEDIO", "BAJO", "MÍNIMO"):
        add(f"    · {nivel:<8}: {by.get(nivel, 0)}")
    add("")
    add(f"  CVEs totales ............ {cve.get('total_cves', 0)}")
    add(f"  CVEs críticos ........... {cve.get('cves_criticos', 0)}")
    add(f"  CVEs en KEV (CISA) ...... {cve.get('cves_en_kev', 0)}")
    add("")
    if prot:
        add("  Exposición de protocolos inseguros:")
        for k, v in prot.items():
            add(f"    · {k:<20}: {v} dispositivos")
    add("")
    top = c.get("top_riesgo", [])
    if top:
        add("  Top dispositivos de mayor riesgo:")
        for i, d in enumerate(top, 1):
            add(f"    {i}. {d.get('ip', '?'):<15} "
                f"{d.get('tipo', '?'):<25} "
                f"{d.get('nivel', '?'):<8} "
                f"(score {d.get('score', 0)}, "
                f"{d.get('cves', 0)} CVEs)")
    add("")
    add("-" * 78)
    add("  INVENTARIO DE DISPOSITIVOS")
    add("-" * 78)
    add("")
    for d in devices:
        ip = d.get("ip", "?")
        risk = d.get("risk_level", "?")
        score = d.get("risk_score", 0)
        add(f"  ▸ {ip}  [{risk}]  (score {score})")
        if d.get("mac"):       add(f"      MAC         : {d['mac']}")
        if d.get("hostname"):  add(f"      Hostname    : {d['hostname']}")
        if d.get("vendor"):    add(f"      Fabricante  : {d['vendor']}")
        if d.get("device_type"): add(f"      Tipo        : {d['device_type']}")
        if d.get("os_guess"):  add(f"      SO          : {d['os_guess']}")

        services = d.get("services", {}) or {}
        if services:
            add(f"      Puertos abiertos:")
            for p, s in sorted(services.items(),
                               key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
                if isinstance(s, dict):
                    name = s.get("name") or s.get("service", "?")
                    prod = s.get("product", "")
                    ver = s.get("version", "")
                    cls = s.get("classification", s.get("security_level", ""))
                    line = f"        [{str(p):>5}] {name:<14} {cls:<10}"
                    if prod: line += f" {prod} {ver}".rstrip()
                    add(line)
                    cves = s.get("cves", []) or []
                    for cve_item in cves[:3]:
                        if isinstance(cve_item, dict):
                            add(f"               ⚠ {cve_item.get('id', '?')} "
                                f"CVSS={cve_item.get('cvss_score', 0)} "
                                f"({cve_item.get('cvss_severity', '?')})")
        findings = d.get("findings", []) or []
        if findings:
            add(f"      Hallazgos:")
            for f in findings:
                if isinstance(f, dict):
                    add(f"        [{f.get('severity', '?')}] "
                        f"{f.get('title', f.get('message', '-'))}")
        add("")
    add("-" * 78)
    add("  RECOMENDACIONES")
    add("-" * 78)
    add("")
    for i, rec in enumerate(c.get("recomendaciones", []), 1):
        if isinstance(rec, dict):
            add(f"  [{rec.get('priority', '-'):<8}] {rec.get('title', '')}")
            desc = rec.get('description', '')
            # word wrap simple
            for line in _wrap(desc, 70):
                add(f"             {line}")
            add("")
        else:
            add(f"  {i:2d}. {rec}")
    add("=" * 78)
    add(f"  Generado por Smart Home Security Audit · {m.get('timestamp', '')}")
    add("=" * 78)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list:
    """Word wrap básico."""
    if not text:
        return []
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 <= width:
            cur = (cur + " " + w).strip()
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


# ============================================================================
#  HTML — diseño sobrio
# ============================================================================
def _build_html(data: dict) -> str:
    m = _get_meta(data)
    devices = _get_devices(data)
    c = _get_conclusions(data)
    r = c.get("resumen", c.get("summary", {}))
    cve = c.get("cve_resumen", {})
    prot = c.get("protocolos_inseguros", {})

    total = r.get("total_dispositivos", r.get("total_devices", 0))
    score_avg = r.get("score_medio", r.get("avg_score", 0))
    risk_global = r.get("riesgo_global", r.get("global_risk", "MÍNIMO"))
    by_level = r.get("por_nivel", r.get("by_risk", {}))

    # Paleta apagada (pastel sobre azul oscuro)
    risk_colors = {
        "CRÍTICO": "#c47878",   # rojo apagado
        "ALTO":    "#c9956b",   # naranja apagado
        "MEDIO":   "#c9b870",   # amarillo apagado
        "BAJO":    "#85b08a",   # verde apagado
        "MÍNIMO":  "#7a9d85",   # verde-gris
    }
    sev_colors = {
        "CRITICAL": "#c47878", "CRITICA": "#c47878",
        "HIGH":     "#c9956b", "ALTA":    "#c9956b",
        "MEDIUM":   "#c9b870", "MEDIA":   "#c9b870",
        "LOW":      "#85b08a", "BAJA":    "#85b08a",
    }
    priority_colors = {
        "URGENTE": "#c47878",
        "ALTA":    "#c9956b",
        "MEDIA":   "#c9b870",
        "BAJA":    "#7a9d85",
    }

    n_crit = by_level.get("CRÍTICO", 0)
    n_alto = by_level.get("ALTO", 0)
    n_med = by_level.get("MEDIO", 0)
    n_bajo = by_level.get("BAJO", 0) + by_level.get("MÍNIMO", 0)
    total_cves = cve.get("total_cves", 0)
    cves_crit = cve.get("cves_criticos", 0)
    cves_kev = cve.get("cves_en_kev", 0)

    donut_svg = _build_donut(n_crit, n_alto, n_med, n_bajo, risk_colors)
    bar_svg = _build_bars(prot)

    # ---- Filas dispositivos ----
    device_rows = []
    for i, d in enumerate(devices):
        ip = d.get("ip", "?")
        mac = d.get("mac", "")
        hostname = d.get("hostname", "")
        vendor = d.get("vendor", "")
        dtype = d.get("device_type", "Desconocido")
        os_guess = d.get("os_guess", "")
        risk_level = d.get("risk_level", "MÍNIMO")
        risk_score = d.get("risk_score", 0)
        risk_color = risk_colors.get(risk_level, "#6b7c8e")

        services = d.get("services", {}) or {}
        # Puertos en lista vertical limpia
        if services:
            port_lines = []
            for p, s in sorted(services.items(),
                               key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
                if isinstance(s, dict):
                    name = s.get("name") or s.get("service", str(p))
                    cls = (s.get("classification", s.get("security_level", "REVISAR"))
                           or "REVISAR").upper()
                    port_lines.append(
                        f"<div class='port-line'>"
                        f"<span class='port-num'>{p}</span>"
                        f"<span class='port-name'>{_esc(name)}</span>"
                        f"<span class='port-cls cls-{cls.lower()}'>{cls}</span>"
                        f"</div>")
            ports_html = "".join(port_lines)
        else:
            ports_html = "<span class='dim'>—</span>"

        n_cves = _count_cves(d)
        n_cves_crit = _count_critical_cves(d)
        if n_cves > 0:
            cves_html = f"<b>{n_cves}</b>"
            if n_cves_crit:
                cves_html += f"<div class='dim small'>{n_cves_crit} críticos</div>"
        else:
            cves_html = "<span class='dim'>—</span>"

        findings = d.get("findings", []) or []
        if findings:
            findings_html = f"<b>{len(findings)}</b>"
        else:
            findings_html = "<span class='dim'>—</span>"

        device_id = f"dev-{i}"
        os_html = f"<div class='dim small'>{_esc(os_guess)}</div>" if os_guess else ""

        device_rows.append(f"""
        <tr class="device-row" onclick="toggleDetails('{device_id}')">
          <td class="ip-col">
            <div class="ip-main">{_esc(ip)}</div>
            <div class="mac">{_esc(mac) or '&nbsp;'}</div>
          </td>
          <td>{_esc(hostname) or "<span class='dim'>—</span>"}</td>
          <td>{_esc(vendor) or "<span class='dim'>—</span>"}</td>
          <td>
            <div>{_esc(dtype)}</div>
            {os_html}
          </td>
          <td class="ports-col">{ports_html}</td>
          <td class="center">{cves_html}</td>
          <td class="center">{findings_html}</td>
          <td>
            <div class="risk-pill" style="background:{risk_color}">{risk_level}</div>
            <div class="dim small center">score {risk_score}</div>
          </td>
        </tr>
        """)

        detail_html = _build_device_detail(d, sev_colors)
        device_rows.append(f"""
        <tr class="device-detail" id="{device_id}" style="display:none">
          <td colspan="8">
            <div class="detail-box">{detail_html}</div>
          </td>
        </tr>
        """)

    # Top riesgo
    top_html = ""
    for i, t in enumerate(c.get("top_riesgo", []), 1):
        nivel = t.get("nivel", "MÍNIMO")
        color = risk_colors.get(nivel, "#6b7c8e")
        top_html += f"""
        <div class="top-item">
          <div class="top-num">{i}</div>
          <div class="top-info">
            <div class="top-line">
              <b class="mono">{_esc(t.get('ip','?'))}</b>
              <span class="top-type">{_esc(t.get('tipo', '?'))}</span>
            </div>
            <div class="top-meta">
              <span class="risk-pill" style="background:{color}">{nivel}</span>
              <span class="dim small">score {t.get('score', 0)} · {t.get('cves', 0)} CVEs</span>
            </div>
          </div>
        </div>
        """

    # Recomendaciones (ahora son dicts con priority/title/description)
    recs = c.get("recomendaciones", [])
    recs_html_parts = []
    for rec in recs:
        if isinstance(rec, dict):
            prio = rec.get("priority", "BAJA")
            color = priority_colors.get(prio, "#7a9d85")
            recs_html_parts.append(f"""
            <div class="rec-item">
              <div class="rec-prio" style="background:{color}">{prio}</div>
              <div class="rec-content">
                <div class="rec-title">{_esc(rec.get('title', ''))}</div>
                <div class="rec-desc">{_esc(rec.get('description', ''))}</div>
              </div>
            </div>
            """)
        else:
            # fallback: si es string
            recs_html_parts.append(f"""
            <div class="rec-item">
              <div class="rec-prio" style="background:#7a9d85">·</div>
              <div class="rec-content"><div class="rec-desc">{_esc(rec)}</div></div>
            </div>
            """)
    recs_html = "".join(recs_html_parts)

    public_ip_html = ""
    if m.get("public_ip"):
        public_ip_html = (f'<div><span class="dim">IP PÚBLICA</span>'
                          f'<div class="mono">{_esc(m.get("public_ip", "-"))}</div></div>')

    rows_joined = ''.join(device_rows) or "<tr><td colspan='8' class='dim center'>Sin dispositivos.</td></tr>"
    total_services = sum(len(d.get('services', {}) or {}) for d in devices)

    return f"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Smart Home Audit · {_esc(m.get('timestamp', ''))}</title>
<style>
{_CSS}
</style>
</head>
<body>

<header>
  <div class="container header-inner">
    <div>
      <div class="logo-line">
        <span class="logo-icon">◆</span>
        <span class="logo-txt">Smart Home Security Audit</span>
      </div>
      <div class="subtitle">Auditoría de ciberseguridad de vivienda inteligente</div>
      <div class="dim small">Proyecto Final ASIX · M14 PAS · Vedruna Vall Terrassa</div>
    </div>
    <div class="header-right">
      <div class="dim small">RIESGO GLOBAL</div>
      <div class="global-risk" style="background:{risk_colors.get(risk_global, '#6b7c8e')}">
        {risk_global}
      </div>
      <div class="dim small">score medio: {score_avg}/100</div>
    </div>
  </div>
</header>

<main class="container">

  <section class="card">
    <div class="meta-grid">
      <div><span class="dim">RED AUDITADA</span><div class="mono">{_esc(m.get('network', '-'))}</div></div>
      <div><span class="dim">INTERFAZ</span><div class="mono">{_esc(m.get('interface', '-'))}</div></div>
      <div><span class="dim">GATEWAY</span><div class="mono">{_esc(m.get('gateway', '-'))}</div></div>
      {public_ip_html}
      <div><span class="dim">FECHA</span><div>{_esc(m.get('timestamp', '-'))}</div></div>
      <div><span class="dim">DURACIÓN</span><div>{m.get('duration', 0):.1f}s</div></div>
      <div><span class="dim">MODO</span><div>{_esc(str(m.get('mode', '-')).upper())}</div></div>
      <div><span class="dim">PUERTOS/HOST</span><div>{m.get('ports_scanned', '-')}</div></div>
    </div>
  </section>

  <section class="kpi-row">
    <div class="kpi"><div class="kpi-num">{total}</div><div class="kpi-lbl">Dispositivos</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#c47878">{n_crit}</div><div class="kpi-lbl">Críticos</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#c9956b">{n_alto}</div><div class="kpi-lbl">Alto riesgo</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#c9b870">{n_med}</div><div class="kpi-lbl">Medio</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#85b08a">{n_bajo}</div><div class="kpi-lbl">Bajo / Mínimo</div></div>
    <div class="kpi"><div class="kpi-num">{total_cves}</div><div class="kpi-lbl">CVEs totales</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#c47878">{cves_crit}</div><div class="kpi-lbl">CVEs críticos</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#c47878">{cves_kev}</div><div class="kpi-lbl">KEV (CISA)</div></div>
  </section>

  <section class="two-col">
    <div class="card">
      <h2>Distribución por nivel de riesgo</h2>
      <div class="chart-wrap">
        {donut_svg}
        <div class="legend">
          <div><span class="dot" style="background:#c47878"></span>Crítico <b>{n_crit}</b></div>
          <div><span class="dot" style="background:#c9956b"></span>Alto <b>{n_alto}</b></div>
          <div><span class="dot" style="background:#c9b870"></span>Medio <b>{n_med}</b></div>
          <div><span class="dot" style="background:#85b08a"></span>Bajo/Mínimo <b>{n_bajo}</b></div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Top dispositivos de mayor riesgo</h2>
      <div class="top-list">
        {top_html or "<div class='dim'>Sin dispositivos con riesgo destacable.</div>"}
      </div>
    </div>
  </section>

  <section class="card">
    <h2>Exposición de protocolos inseguros</h2>
    <p class="dim">Número de dispositivos en la red exponiendo cada protocolo.</p>
    {bar_svg}
  </section>

  <section class="card">
    <h2>Inventario de dispositivos</h2>
    <p class="dim">Haz clic en cualquier fila para ver el detalle de servicios y CVEs.</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>IP / MAC</th>
            <th>Hostname</th>
            <th>Fabricante</th>
            <th>Tipo / SO</th>
            <th>Puertos abiertos</th>
            <th class="center">CVEs</th>
            <th class="center">Hallazgos</th>
            <th class="center">Riesgo</th>
          </tr>
        </thead>
        <tbody>
          {rows_joined}
        </tbody>
      </table>
    </div>
  </section>

  <section class="card">
    <h2>Recomendaciones</h2>
    <p class="dim">Recomendaciones generadas a partir de los hallazgos detectados, ordenadas por prioridad.</p>
    <div class="recs-list">
      {recs_html or "<div class='dim'>Sin recomendaciones.</div>"}
    </div>
  </section>

</main>

<footer>
  <div class="container">
    <div class="dim small">
      Smart Home Security Audit · Generado el {_esc(m.get('timestamp', ''))}
    </div>
    <div class="dim small">
      {len(devices)} dispositivos · {total_services} servicios · {total_cves} CVEs
    </div>
  </div>
</footer>

<script>
function toggleDetails(id) {{
  var el = document.getElementById(id);
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</body></html>"""


def _build_device_detail(d: dict, sev_colors: dict) -> str:
    out = []
    services = d.get("services", {}) or {}
    findings = d.get("findings", []) or []
    discovery = d.get("discovery_methods", []) or []

    if discovery:
        chips = "".join(f"<span class='chip'>{_esc(x)}</span>" for x in discovery)
        out.append(f"<div class='detail-section'><h4>Métodos de descubrimiento</h4>{chips}</div>")

    if services:
        out.append("<div class='detail-section'><h4>Servicios detectados</h4>")
        for p, s in sorted(services.items(),
                           key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
            if not isinstance(s, dict):
                continue
            name = s.get("name") or s.get("service", "?")
            cls = (s.get("classification", s.get("security_level", "REVISAR")) or "REVISAR").lower()
            banner = s.get("banner", "")
            product = s.get("product", "")
            version = s.get("version", "")
            cpe = s.get("cpe", "")
            cves = s.get("cves", []) or []

            product_html = (f"<div class='kv'><span class='dim'>Producto:</span> "
                            f"<b>{_esc(product)}</b> "
                            f"<span class='dim'>v{_esc(version)}</span></div>"
                            if product else "")
            banner_html = (f"<div class='kv'><span class='dim'>Banner:</span> "
                           f"<code>{_esc(banner[:200])}</code></div>"
                           if banner else "")
            cpe_html = (f"<div class='kv'><span class='dim'>CPE:</span> "
                        f"<code class='small'>{_esc(cpe)}</code></div>"
                        if cpe else "")

            out.append(f"""
            <div class="service-detail">
              <div class="service-head">
                <span class="port-num-large">{p}</span>
                <span class="port-name-large">{_esc(name)}</span>
                <span class="cls-badge cls-{cls}">{cls.upper()}</span>
              </div>
              {product_html}
              {banner_html}
              {cpe_html}
            """)
            if cves:
                out.append("<div class='cves-list'>")
                for cve in cves:
                    if not isinstance(cve, dict):
                        continue
                    sev = cve.get("cvss_severity", "").upper()
                    sev_color = sev_colors.get(sev, "#6b7c8e")
                    cve_id = cve.get("id", "?")
                    cve_url = cve.get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                    score = cve.get("cvss_score", 0)
                    desc = cve.get("description", "")[:300]
                    kev = "<span class='kev-badge'>EXPLOTADO ACTIVAMENTE (KEV)</span>" if cve.get("in_kev") else ""
                    out.append(f"""
                    <div class="cve-item">
                      <div class="cve-head">
                        <a href="{_esc(cve_url)}" target="_blank" class="cve-id">{_esc(cve_id)}</a>
                        <span class="cvss" style="background:{sev_color}">CVSS {score} · {sev}</span>
                        {kev}
                      </div>
                      <div class="cve-desc">{_esc(desc)}</div>
                    </div>
                    """)
                out.append("</div>")
            out.append("</div>")
        out.append("</div>")

    if findings:
        out.append("<div class='detail-section'><h4>Hallazgos</h4>")
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = f.get("severity", "?").upper()
            color = sev_colors.get(sev, "#6b7c8e")
            title = f.get("title", f.get("message", ""))
            desc = f.get("description", "")
            rec = f.get("recommendation", "")
            desc_html = f"<div class='dim small'>{_esc(desc)}</div>" if desc else ""
            rec_html = f"<div class='rec-inline'>↪ {_esc(rec)}</div>" if rec else ""
            out.append(f"""
            <div class="finding-item">
              <span class="sev-pill" style="background:{color}">{sev}</span>
              <b>{_esc(title)}</b>
              {desc_html}
              {rec_html}
            </div>
            """)
        out.append("</div>")

    if not out:
        out.append("<div class='dim center pad'>Sin información adicional.</div>")
    return "".join(out)


# ============================================================================
#  Gráficos SVG
# ============================================================================
def _build_donut(crit, alto, med, bajo, colors) -> str:
    total = crit + alto + med + bajo
    if total == 0:
        return ('<div class="dim center pad" style="width:200px;height:200px;'
                'display:flex;align-items:center;justify-content:center;flex-shrink:0">'
                'Sin datos</div>')

    segments = [
        (crit, colors["CRÍTICO"]),
        (alto, colors["ALTO"]),
        (med, colors["MEDIO"]),
        (bajo, colors["BAJO"]),
    ]

    cx, cy, r = 100, 100, 70
    stroke = 22
    circumference = 2 * 3.14159265 * r

    paths = []
    accumulated = 0
    for value, color in segments:
        if value <= 0:
            continue
        fraction = value / total
        dasharray = f"{fraction * circumference} {circumference}"
        rotation = -90 + (accumulated / total) * 360
        paths.append(f"""
        <circle cx="{cx}" cy="{cy}" r="{r}"
                fill="none" stroke="{color}" stroke-width="{stroke}"
                stroke-dasharray="{dasharray}"
                transform="rotate({rotation} {cx} {cy})"/>
        """)
        accumulated += value

    return f"""
    <svg class="donut" viewBox="0 0 200 200" width="200" height="200">
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
              stroke="#1c2940" stroke-width="{stroke}"/>
      {''.join(paths)}
      <text x="{cx}" y="{cy - 8}" text-anchor="middle"
            fill="#cbd5e1" font-size="32" font-weight="600">{total}</text>
      <text x="{cx}" y="{cy + 14}" text-anchor="middle"
            fill="#7d8fa3" font-size="11" letter-spacing="1">DISPOSITIVOS</text>
    </svg>
    """


def _build_bars(prot: dict) -> str:
    if not prot:
        return "<div class='dim'>Sin datos de protocolos.</div>"

    labels = {
        "telnet":       "Telnet (23/2323)",
        "ftp":          "FTP (21)",
        "http_sin_tls": "HTTP sin TLS",
        "smb_netbios":  "SMB / NetBIOS",
        "upnp":         "UPnP",
        "cleartext_total": "Cleartext total",
    }
    items = [(labels.get(k, k), v) for k, v in prot.items()]
    max_val = max((v for _, v in items), default=1) or 1

    rows = []
    for label, value in items:
        pct = (value / max_val) * 100 if max_val else 0
        if value == 0:
            color = "#3a4d5e"
        elif value >= 3:
            color = "#c47878"
        elif value >= 1:
            color = "#c9956b"
        else:
            color = "#85b08a"
        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label">{_esc(label)}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%; background:{color}"></div>
          </div>
          <div class="bar-value">{value}</div>
        </div>
        """)
    return f'<div class="bars">{"".join(rows)}</div>'


def _esc(s) -> str:
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ============================================================================
#  CSS — sobrio, sin glow, sin neón
# ============================================================================
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  /* Fondos */
  --bg-page:    #131c2b;     /* azul oscuro casi negro */
  --bg-card:    #1a2436;     /* azul oscuro suave */
  --bg-card2:   #202d42;     /* un poco más claro */
  --bg-elev:    #283854;
  /* Bordes */
  --border:     #283854;
  --border-soft:#1f2c40;
  /* Texto */
  --text:       #c5d0dc;     /* azul claro suave */
  --text-soft:  #a0adbf;
  --text-dim:   #7d8fa3;
  --text-mut:   #5a6b80;
  /* Acento sobrio (azul gris, no cyan) */
  --accent:     #7ba3c4;
  /* Severidades pastel */
  --crit:       #c47878;
  --alto:       #c9956b;
  --med:        #c9b870;
  --bajo:       #85b08a;
}

html, body {
  background: var(--bg-page);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

.container { max-width: 1400px; margin: 0 auto; padding: 0 24px; }

/* ------------------ Header ------------------ */
header {
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
  padding: 28px 0;
}
.header-inner {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 24px; flex-wrap: wrap;
}
.logo-line {
  display: flex; align-items: center; gap: 10px;
  font-size: 20px; font-weight: 600; color: var(--text);
}
.logo-icon { color: var(--accent); font-size: 18px; }
.logo-txt { letter-spacing: -0.01em; }
.subtitle { color: var(--text-soft); margin-top: 4px; font-size: 13px; }
.small { font-size: 11px; }
.header-right { text-align: right; min-width: 200px; }
.global-risk {
  display: inline-block;
  color: white;
  padding: 8px 18px;
  font-size: 18px;
  font-weight: 600;
  border-radius: 4px;
  margin: 6px 0;
  letter-spacing: 0.04em;
}

/* ------------------ Cards ------------------ */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 22px 24px;
  margin: 20px 0;
}
.card h2 {
  color: var(--text);
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 6px;
  letter-spacing: 0.01em;
}
.card p { color: var(--text-dim); margin-bottom: 14px; font-size: 13px; }

.dim { color: var(--text-dim); font-size: 11px; letter-spacing: 0.06em; }
.mono { font-family: "SF Mono", Consolas, "Liberation Mono", monospace; }

/* ------------------ Meta grid ------------------ */
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 16px;
}
.meta-grid > div {
  padding: 6px 0 6px 12px;
  border-left: 2px solid var(--border);
}

/* ------------------ KPIs ------------------ */
.kpi-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(135px, 1fr));
  gap: 10px; margin: 20px 0;
}
.kpi {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px 14px;
  text-align: center;
  transition: border-color 0.15s, transform 0.15s;
}
.kpi:hover {
  border-color: var(--accent);
  transform: translateY(-1px);
}
.kpi-num {
  font-size: 28px;
  font-weight: 600;
  line-height: 1;
  color: var(--text);
  font-feature-settings: "tnum";
}
.kpi-lbl {
  color: var(--text-dim);
  font-size: 11px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  margin-top: 6px;
}

/* ------------------ Two col layout ------------------ */
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
@media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
.two-col .card { margin: 0; }

/* ------------------ Donut ------------------ */
.chart-wrap { display: flex; gap: 28px; align-items: center; padding: 16px 0; }
.donut { flex-shrink: 0; }
.legend { flex: 1; display: flex; flex-direction: column; gap: 8px; }
.legend > div {
  display: flex; align-items: center; gap: 10px;
  padding: 6px 0;
  border-bottom: 1px solid var(--border-soft);
  font-size: 13px;
}
.legend > div:last-child { border-bottom: none; }
.dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.legend b { margin-left: auto; color: var(--text); font-weight: 600; }

/* ------------------ Top items ------------------ */
.top-list { display: flex; flex-direction: column; gap: 8px; }
.top-item {
  display: flex; align-items: center; gap: 12px;
  padding: 11px 12px;
  background: var(--bg-card2);
  border-radius: 4px;
  border-left: 2px solid var(--border);
  transition: border-left-color 0.15s;
}
.top-item:hover { border-left-color: var(--accent); }
.top-num {
  width: 26px; height: 26px; border-radius: 50%;
  background: var(--bg-page); color: var(--text-dim);
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 600; flex-shrink: 0;
  border: 1px solid var(--border);
}
.top-info { flex: 1; min-width: 0; }
.top-line { display: flex; gap: 8px; flex-wrap: wrap; align-items: baseline; }
.top-line b { color: var(--text); }
.top-type { color: var(--text-soft); font-size: 13px; }
.top-meta {
  display: flex; gap: 10px; align-items: center;
  margin-top: 4px; flex-wrap: wrap;
}

/* ------------------ Bars ------------------ */
.bars { display: flex; flex-direction: column; gap: 10px; padding-top: 4px; }
.bar-row {
  display: grid;
  grid-template-columns: 200px 1fr 50px;
  gap: 12px; align-items: center;
}
.bar-label { color: var(--text-soft); font-size: 13px; }
.bar-track {
  background: var(--bg-card2);
  border-radius: 2px; overflow: hidden;
  height: 18px;
  border: 1px solid var(--border-soft);
}
.bar-fill {
  height: 100%;
  transition: width 0.6s ease-out;
}
.bar-value {
  font-family: "SF Mono", Consolas, monospace;
  font-weight: 600;
  color: var(--text);
  text-align: right;
  font-size: 13px;
}

/* ------------------ Risk pill ------------------ */
.risk-pill {
  display: inline-block;
  color: white;
  padding: 3px 10px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

/* ------------------ Tabla inventario ------------------ */
.table-wrap { overflow-x: auto; margin: 0 -8px; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  min-width: 1100px;
}
th {
  text-align: left;
  padding: 10px 12px;
  background: var(--bg-card2);
  color: var(--text-soft);
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: top;
}
.center { text-align: center; }
.device-row { cursor: pointer; transition: background 0.1s; }
.device-row:hover { background: var(--bg-card2); }
.device-row td { color: var(--text); }

.ip-col { white-space: nowrap; }
.ip-main { font-weight: 600; font-family: "SF Mono", Consolas, monospace; color: var(--text); }
.mac { color: var(--text-mut); font-family: "SF Mono", Consolas, monospace; font-size: 11px; }

/* ---- Puertos: lista vertical limpia ---- */
.ports-col {
  min-width: 240px;
  max-width: 280px;
}
.port-line {
  display: grid;
  grid-template-columns: 50px 1fr auto;
  gap: 8px;
  padding: 3px 0;
  align-items: center;
  font-size: 12px;
}
.port-num {
  font-family: "SF Mono", Consolas, monospace;
  font-weight: 600;
  color: var(--accent);
  text-align: right;
}
.port-name {
  color: var(--text-soft);
  font-size: 12px;
}
.port-cls {
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.04em;
  padding: 2px 6px;
  border-radius: 2px;
}
.cls-seguro   { background: rgba(133, 176, 138, 0.15); color: #98c79c; }
.cls-neutro   { background: rgba(123, 163, 196, 0.15); color: #9ebcd6; }
.cls-revisar  { background: rgba(201, 184, 112, 0.15); color: #d4c688; }
.cls-inseguro { background: rgba(201, 149, 107, 0.15); color: #dba98a; }
.cls-critico  { background: rgba(196, 120, 120, 0.18); color: #d99595; }

/* ------------------ Detalle expandible ------------------ */
.device-detail td { padding: 0; background: var(--bg-page); }
.detail-box {
  padding: 18px 22px;
  border-left: 2px solid var(--accent);
  background: var(--bg-card);
}
.detail-section { margin-bottom: 18px; }
.detail-section:last-child { margin-bottom: 0; }
.detail-section h4 {
  color: var(--text-soft);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 10px;
  font-weight: 600;
}
.chip {
  display: inline-block;
  padding: 3px 10px;
  margin: 2px;
  background: var(--bg-card2);
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-soft);
  font-size: 11px;
}
.service-detail {
  background: var(--bg-card2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 12px 14px;
  margin-bottom: 8px;
}
.service-head {
  display: flex; gap: 10px; align-items: center;
  margin-bottom: 8px; flex-wrap: wrap;
}
.port-num-large {
  font-family: "SF Mono", Consolas, monospace;
  color: var(--accent);
  font-weight: 700;
  font-size: 15px;
}
.port-name-large {
  color: var(--text);
  font-weight: 500;
  font-size: 13px;
}
.cls-badge {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 2px 8px;
  border-radius: 2px;
  margin-left: auto;
}
.kv { font-size: 12px; padding: 3px 0; color: var(--text-soft); }
.kv code {
  background: var(--bg-page);
  padding: 2px 6px;
  border-radius: 2px;
  font-size: 11px;
  color: var(--text);
  border: 1px solid var(--border);
  font-family: "SF Mono", Consolas, monospace;
}

/* ------------------ CVEs ------------------ */
.cves-list { margin-top: 10px; }
.cve-item {
  background: var(--bg-page);
  border-left: 2px solid var(--crit);
  padding: 9px 14px;
  margin: 6px 0;
  border-radius: 0 3px 3px 0;
}
.cve-head {
  display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
}
.cve-id {
  color: var(--accent);
  font-weight: 600;
  text-decoration: none;
  font-family: "SF Mono", Consolas, monospace;
  font-size: 12px;
}
.cve-id:hover { text-decoration: underline; }
.cvss {
  color: white;
  padding: 2px 8px;
  border-radius: 2px;
  font-size: 11px;
  font-weight: 600;
  font-family: "SF Mono", Consolas, monospace;
}
.kev-badge {
  background: var(--crit);
  color: white;
  padding: 2px 8px;
  border-radius: 2px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.04em;
}
.cve-desc { color: var(--text-dim); font-size: 12px; margin-top: 6px; line-height: 1.5; }

/* ------------------ Findings ------------------ */
.finding-item {
  background: var(--bg-card2);
  padding: 10px 14px;
  border-radius: 4px;
  margin: 6px 0;
  border-left: 2px solid var(--border);
}
.sev-pill {
  color: white;
  padding: 2px 8px;
  border-radius: 2px;
  font-size: 10px;
  font-weight: 700;
  margin-right: 8px;
  letter-spacing: 0.04em;
}
.rec-inline {
  color: var(--text-soft);
  font-size: 12px;
  margin-top: 4px;
  padding-left: 10px;
  border-left: 2px solid var(--border-soft);
}

/* ------------------ Recomendaciones ------------------ */
.recs-list { display: flex; flex-direction: column; gap: 10px; margin-top: 8px; }
.rec-item {
  display: grid;
  grid-template-columns: 70px 1fr;
  gap: 14px;
  padding: 14px;
  background: var(--bg-card2);
  border-radius: 4px;
  border-left: 2px solid var(--border);
  transition: border-left-color 0.15s;
}
.rec-item:hover { border-left-color: var(--accent); }
.rec-prio {
  color: white;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 4px 8px;
  border-radius: 3px;
  text-align: center;
  height: fit-content;
  align-self: flex-start;
}
.rec-content {}
.rec-title {
  color: var(--text);
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 4px;
}
.rec-desc {
  color: var(--text-soft);
  font-size: 13px;
  line-height: 1.6;
}

/* ------------------ Footer ------------------ */
footer {
  padding: 22px 0;
  border-top: 1px solid var(--border);
  margin-top: 30px;
  background: var(--bg-card);
}
footer .container {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}

/* ------------------ Print ------------------ */
.pad { padding: 24px; }
.dim.center { text-align: center; }

@media print {
  body { background: white; color: #1a2436; }
  header, footer { background: #f3f4f6; color: #1a2436; }
  .card, .kpi { break-inside: avoid; background: white; border-color: #d1d5db; }
  .device-detail { display: table-row !important; }
  .dim, .text-soft { color: #4b5563 !important; }
}
"""
