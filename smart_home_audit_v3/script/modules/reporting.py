"""
===============================================================================
 modules/reporting.py
 -----------------------------------------------------------------------------
 Generación de informes en múltiples formatos:
   - JSON: datos estructurados completos
   - TXT:  resumen plano para terminal/email
   - HTML: informe visual estilo ciberseguridad / dashboard

 Diseño HTML: tema oscuro azul cyberpunk (paleta del proyecto)
   Fondo:       #0a1929 / #0f2342  (azul muy oscuro)
   Cards:       #1e3a5f / #1a2f4f  (azul medio)
   Texto:       #e0f2ff             (azul muy claro)
   Acento:      #00d4ff             (cyan eléctrico)
   Crítico:     #ef4444             (rojo)
   Alto:        #f97316             (naranja)
   Medio:       #eab308             (amarillo)
   Bajo:        #22c55e             (verde)
===============================================================================
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Tuple


# ============================================================================
#  ENTRY POINT — guarda los 3 formatos
# ============================================================================
def save_all_reports(report, outdir: Path = None) -> Tuple[Path, Path, Path]:
    """
    Acepta:
      - un objeto AuditReport (con .meta, .devices, .conclusions)
      - O un dict con la misma estructura
    Devuelve (json_path, txt_path, html_path).
    """
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
#  Serialización flexible
# ============================================================================
def _to_dict(report) -> dict:
    if isinstance(report, dict):
        return report
    if hasattr(report, "to_dict"):
        return report.to_dict()
    out = {}
    if hasattr(report, "meta"):
        out["meta"] = _obj_to_dict(report.meta)
    if hasattr(report, "metadata"):
        out["metadata"] = _obj_to_dict(report.metadata)
    if hasattr(report, "devices"):
        out["devices"] = [_obj_to_dict(d) for d in report.devices]
    if hasattr(report, "conclusions"):
        out["conclusions"] = _obj_to_dict(report.conclusions)
    if hasattr(report, "summary"):
        out["summary"] = _obj_to_dict(report.summary)
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
    total = len(devices)
    by_level = {"CRÍTICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "MÍNIMO": 0}
    score_sum = 0
    total_cves = 0
    critical_cves = 0
    high_cves = 0
    n_telnet = n_ftp = n_http = n_smb = n_upnp = 0

    for d in devices:
        lvl = d.get("risk_level", "MÍNIMO")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        score_sum += d.get("risk_score", 0)
        ports = d.get("open_ports", []) or list(d.get("services", {}).keys())
        ports_int = []
        for p in ports:
            try:
                ports_int.append(int(p))
            except (ValueError, TypeError):
                pass
        if any(p in ports_int for p in (23, 2323)): n_telnet += 1
        if 21 in ports_int: n_ftp += 1
        if any(p in ports_int for p in (80, 8080, 8000, 8081, 8088)): n_http += 1
        if any(p in ports_int for p in (139, 445)): n_smb += 1
        if any(p in ports_int for p in (1900, 5000, 49152)): n_upnp += 1

        services = d.get("services", {})
        if isinstance(services, dict):
            for s in services.values():
                cves = s.get("cves", []) if isinstance(s, dict) else []
                total_cves += len(cves)
                for cv in cves:
                    sev = (cv.get("cvss_severity", "") if isinstance(cv, dict) else "").upper()
                    if sev == "CRITICAL": critical_cves += 1
                    elif sev == "HIGH": high_cves += 1

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
            "cves_en_kev": 0,
        },
        "protocolos_inseguros": {
            "telnet": n_telnet, "ftp": n_ftp, "http_sin_tls": n_http,
            "smb_netbios": n_smb, "upnp": n_upnp,
        },
        "top_riesgo": [
            {"ip": d.get("ip", "?"),
             "tipo": d.get("device_type", "Desconocido"),
             "score": d.get("risk_score", 0),
             "nivel": d.get("risk_level", "MÍNIMO"),
             "cves": _count_cves(d),
             "cves_criticos": _count_critical_cves(d)}
            for d in sorted(devices, key=lambda x: -x.get("risk_score", 0))[:5]
        ],
        "recomendaciones": _generate_recommendations(
            n_telnet, n_ftp, n_http, n_smb, n_upnp, critical_cves),
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

def _generate_recommendations(telnet, ftp, http, smb, upnp, critical_cves):
    recs = []
    if critical_cves:
        recs.append(f"Se han identificado {critical_cves} vulnerabilidades "
                    f"CRÍTICAS (CVSS 9.0+). Aplicar parches del fabricante de inmediato.")
    if telnet:
        recs.append("Deshabilitar Telnet (puertos 23/2323) en TODOS los dispositivos. "
                    "Es vector usado por botnets como Mirai.")
    if ftp:
        recs.append("Sustituir FTP por SFTP/FTPS o desactivarlo. "
                    "FTP transmite credenciales en texto plano.")
    if http:
        recs.append("Los paneles de admin por HTTP plano son interceptables. "
                    "Forzar HTTPS o restringir a red interna.")
    if smb:
        recs.append("Revisar SMB/NetBIOS: deshabilitar SMBv1 y no exponer "
                    "estos puertos a internet.")
    if upnp:
        recs.append("Desactivar UPnP en el router: abre puertos automáticamente "
                    "sin consentimiento.")
    recs.extend([
        "Mantener firmware del router y todos los IoT actualizados.",
        "Separar la red IoT mediante SSID de invitados o VLAN dedicada.",
        "Cambiar credenciales por defecto en TODOS los dispositivos.",
        "Usar WPA3 (o WPA2-AES) con contraseñas robustas (>16 caracteres).",
        "Activar el cortafuegos del router y bloquear tráfico entrante no solicitado.",
        "Ejecutar esta auditoría periódicamente y comparar resultados.",
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
                    line = f"        [{str(p):>5}] {name:<12}"
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
        add(f"  {i:2d}. {rec}")
    add("")
    add("=" * 78)
    add(f"  Generado por Smart Home Security Audit · "
        f"{m.get('timestamp', datetime.now().isoformat())}")
    add("=" * 78)
    return "\n".join(lines)


# ============================================================================
#  HTML — tema cyber azul oscuro
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

    risk_colors = {
        "CRÍTICO": "#ef4444",
        "ALTO":    "#f97316",
        "MEDIO":   "#eab308",
        "BAJO":    "#22c55e",
        "MÍNIMO":  "#10b981",
    }
    sev_colors = {
        "CRITICAL": "#ef4444", "CRITICA": "#ef4444",
        "HIGH":     "#f97316", "ALTA":    "#f97316",
        "MEDIUM":   "#eab308", "MEDIA":   "#eab308",
        "LOW":      "#22c55e", "BAJA":    "#22c55e",
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

    # Filas dispositivos
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
        risk_color = risk_colors.get(risk_level, "#64748b")

        services = d.get("services", {}) or {}
        if services:
            chips = []
            for p, s in sorted(services.items(),
                               key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
                if isinstance(s, dict):
                    cls = (s.get("classification", s.get("security_level", "REVISAR"))
                           or "REVISAR").lower()
                    name = s.get("name") or s.get("service", str(p))
                    chips.append(
                        f"<span class='port port-{cls}'>{p}/{name}</span>")
            ports_html = " ".join(chips)
        else:
            ports_html = "<span class='dim'>—</span>"

        n_cves = _count_cves(d)
        n_cves_crit = _count_critical_cves(d)
        if n_cves > 0:
            cves_html = f"<b>{n_cves}</b>"
            if n_cves_crit:
                cves_html += f" <span class='badge-crit'>{n_cves_crit} crit</span>"
        else:
            cves_html = "<span class='dim'>—</span>"

        findings = d.get("findings", []) or []
        findings_html = (f"<b>{len(findings)}</b> hallazgo{'s' if len(findings)!=1 else ''}"
                         if findings else "<span class='dim'>—</span>")

        device_id = f"dev-{i}"
        os_guess_html = f"<div class='dim small'>{_esc(os_guess)}</div>" if os_guess else ""

        device_rows.append(f"""
        <tr class="device-row" onclick="toggleDetails('{device_id}')">
          <td>
            <div class="ip-cell">
              <span class="status-dot" style="background:{risk_color}"></span>
              <div>
                <b>{_esc(ip)}</b>
                <div class="mac">{_esc(mac) or '&nbsp;'}</div>
              </div>
            </div>
          </td>
          <td>{_esc(hostname) or "<span class='dim'>—</span>"}</td>
          <td>{_esc(vendor) or "<span class='dim'>—</span>"}</td>
          <td>
            <b>{_esc(dtype)}</b>
            {os_guess_html}
          </td>
          <td class="ports-cell">{ports_html}</td>
          <td class="center">{cves_html}</td>
          <td class="center">{findings_html}</td>
          <td>
            <div class="risk-pill" style="background:{risk_color}">{risk_level}</div>
            <div class="dim small">score: {risk_score}</div>
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
        color = risk_colors.get(nivel, "#64748b")
        top_html += f"""
        <div class="top-item">
          <div class="top-num" style="border-color:{color}; color:{color}">{i}</div>
          <div class="top-info">
            <div class="top-line">
              <b class="mono">{_esc(t.get('ip','?'))}</b>
              <span class="top-type">· {_esc(t.get('tipo', '?'))}</span>
            </div>
            <div class="top-meta">
              <span class="risk-pill" style="background:{color}">{nivel}</span>
              <span class="dim">score {t.get('score', 0)}</span>
              <span class="dim">·</span>
              <span class="dim">{t.get('cves', 0)} CVEs</span>
            </div>
          </div>
        </div>
        """

    recs = c.get("recomendaciones", [])
    recs_html = "".join(
        f"<li><span class='rec-num'>{i:02d}</span>{_esc(rr)}</li>"
        for i, rr in enumerate(recs, 1))

    public_ip_html = ""
    if m.get("public_ip"):
        public_ip_html = (f'<div><span class="dim">IP PÚBLICA</span>'
                          f'<div class="mono">{_esc(m.get("public_ip", "-"))}</div></div>')

    pulse_class = "pulse" if cves_kev else ""
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

<div class="grid-bg"></div>

<header>
  <div class="container header-inner">
    <div>
      <div class="logo-line">
        <span class="logo-icon">⬢</span>
        <span class="logo-txt">SMART HOME <span class="cyan">SECURITY AUDIT</span></span>
      </div>
      <div class="subtitle">Auditoría de ciberseguridad de vivienda inteligente</div>
      <div class="dim small">Proyecto Final ASIX · M14 PAS · Vedruna Vall Terrassa</div>
    </div>
    <div class="header-right">
      <div class="dim small">RIESGO GLOBAL</div>
      <div class="global-risk" style="background:{risk_colors.get(risk_global, '#64748b')}">
        {risk_global}
      </div>
      <div class="dim small">score medio: {score_avg}/100</div>
    </div>
  </div>
</header>

<main class="container">

  <section class="card">
    <div class="meta-grid">
      <div><span class="dim">RED AUDITADA</span><div class="mono cyan">{_esc(m.get('network', '-'))}</div></div>
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
    <div class="kpi"><div class="kpi-num cyan">{total}</div><div class="kpi-lbl">Dispositivos</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#ef4444">{n_crit}</div><div class="kpi-lbl">Críticos</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#f97316">{n_alto}</div><div class="kpi-lbl">Alto riesgo</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#eab308">{n_med}</div><div class="kpi-lbl">Medio</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#22c55e">{n_bajo}</div><div class="kpi-lbl">Bajo / Mínimo</div></div>
    <div class="kpi"><div class="kpi-num cyan">{total_cves}</div><div class="kpi-lbl">CVEs totales</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#ef4444">{cves_crit}</div><div class="kpi-lbl">CVEs críticos</div></div>
    <div class="kpi {pulse_class}"><div class="kpi-num" style="color:#ef4444">{cves_kev}</div><div class="kpi-lbl">KEV (CISA)</div></div>
  </section>

  <section class="two-col">
    <div class="card">
      <h2>// Distribución por nivel de riesgo</h2>
      <div class="chart-wrap">
        {donut_svg}
        <div class="legend">
          <div><span class="dot" style="background:#ef4444"></span>Crítico <b>{n_crit}</b></div>
          <div><span class="dot" style="background:#f97316"></span>Alto <b>{n_alto}</b></div>
          <div><span class="dot" style="background:#eab308"></span>Medio <b>{n_med}</b></div>
          <div><span class="dot" style="background:#22c55e"></span>Bajo/Mínimo <b>{n_bajo}</b></div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>// Top 5 dispositivos de mayor riesgo</h2>
      <div class="top-list">
        {top_html or "<div class='dim'>Sin dispositivos detectados.</div>"}
      </div>
    </div>
  </section>

  <section class="card">
    <h2>// Exposición de protocolos inseguros</h2>
    <p class="dim">Número de dispositivos en la red exponiendo cada protocolo.</p>
    {bar_svg}
  </section>

  <section class="card">
    <h2>// Inventario de dispositivos detectados</h2>
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
            <th>Riesgo</th>
          </tr>
        </thead>
        <tbody>
          {rows_joined}
        </tbody>
      </table>
    </div>
  </section>

  <section class="card recs-card">
    <h2>// Recomendaciones priorizadas</h2>
    <ol class="recs">
      {recs_html or "<li class='dim'>Sin recomendaciones.</li>"}
    </ol>
  </section>

</main>

<footer>
  <div class="container">
    <div class="dim small">
      Smart Home Security Audit · v2.0 · Generado el {_esc(m.get('timestamp', ''))}
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
document.addEventListener('DOMContentLoaded', function() {{
  document.querySelectorAll('.kpi-num').forEach(function(el) {{
    var target = parseInt(el.textContent, 10);
    if (isNaN(target) || target === 0) return;
    var cur = 0;
    var step = Math.max(1, Math.floor(target / 30));
    var t = setInterval(function() {{
      cur += step;
      if (cur >= target) {{ el.textContent = target; clearInterval(t); }}
      else {{ el.textContent = cur; }}
    }}, 30);
  }});
}});
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
                <span class="port port-{cls}">{p}/{_esc(name)}</span>
                <span class="cls cls-{cls}">{cls.upper()}</span>
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
                    sev_color = sev_colors.get(sev, "#64748b")
                    cve_id = cve.get("id", "?")
                    cve_url = cve.get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                    score = cve.get("cvss_score", 0)
                    desc = cve.get("description", "")[:300]
                    kev = "<span class='kev-badge'>⚠ EXPLOTADO ACTIVAMENTE</span>" if cve.get("in_kev") else ""
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
            color = sev_colors.get(sev, "#64748b")
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
#  GRÁFICOS SVG
# ============================================================================
def _build_donut(crit, alto, med, bajo, colors) -> str:
    total = crit + alto + med + bajo
    if total == 0:
        return ('<div class="dim center pad" style="height:200px;width:200px;'
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
              stroke="#1e3a5f" stroke-width="{stroke}"/>
      {''.join(paths)}
      <text x="{cx}" y="{cy - 8}" text-anchor="middle"
            fill="#e0f2ff" font-size="32" font-weight="700">{total}</text>
      <text x="{cx}" y="{cy + 14}" text-anchor="middle"
            fill="#94a3b8" font-size="11">DISPOSITIVOS</text>
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
        color = "#ef4444" if value >= 3 else ("#f97316" if value >= 1 else "#22c55e")
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


# ============================================================================
#  Helpers
# ============================================================================
def _esc(s) -> str:
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ============================================================================
#  CSS — Tema cyber azul oscuro
# ============================================================================
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg-darkest: #050d1a;
  --bg-dark:    #0a1929;
  --bg-card:    #0f2342;
  --bg-card2:   #122a4d;
  --bg-elev:    #1a3563;
  --border:     #1e3a5f;
  --border-lt:  #2c4870;
  --text:       #e0f2ff;
  --text-dim:   #94a3b8;
  --text-mut:   #64748b;
  --cyan:       #00d4ff;
  --cyan-glow:  #00d4ff66;
  --blue:       #3b82f6;
  --crit:       #ef4444;
  --alto:       #f97316;
  --med:        #eab308;
  --bajo:       #22c55e;
}

html, body {
  background: var(--bg-darkest);
  color: var(--text);
  font-family: -apple-system, "Segoe UI", "Inter", Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.55;
  min-height: 100vh;
}

.grid-bg {
  position: fixed; inset: 0; z-index: -1;
  background:
    linear-gradient(var(--bg-darkest), var(--bg-dark)),
    repeating-linear-gradient(0deg, transparent 0, transparent 39px, #1e3a5f22 39px, #1e3a5f22 40px),
    repeating-linear-gradient(90deg, transparent 0, transparent 39px, #1e3a5f22 39px, #1e3a5f22 40px);
}
.grid-bg::after {
  content: ''; position: absolute; inset: 0;
  background: radial-gradient(circle at 30% 20%, #00d4ff15 0%, transparent 50%),
              radial-gradient(circle at 80% 70%, #3b82f615 0%, transparent 50%);
  pointer-events: none;
}

.container { max-width: 1400px; margin: 0 auto; padding: 0 24px; }

header {
  background: linear-gradient(135deg, #0a1929 0%, #0f2342 100%);
  border-bottom: 1px solid var(--border);
  padding: 32px 0;
  position: relative;
  overflow: hidden;
}
header::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--cyan), transparent);
}
.header-inner { display: flex; justify-content: space-between; align-items: center; gap: 24px; flex-wrap: wrap; }
.logo-line { display: flex; align-items: center; gap: 12px; font-size: 22px; font-weight: 700; letter-spacing: 0.02em; }
.logo-icon { color: var(--cyan); font-size: 28px; text-shadow: 0 0 12px var(--cyan-glow); }
.logo-txt { color: var(--text); }
.cyan { color: var(--cyan) !important; }
.subtitle { color: var(--text-dim); margin-top: 6px; font-size: 13px; }
.small { font-size: 11px; }
.header-right { text-align: right; }
.global-risk {
  display: inline-block; color: white; padding: 10px 22px;
  font-size: 24px; font-weight: 700; letter-spacing: 0.05em;
  border-radius: 4px; margin: 6px 0;
  box-shadow: 0 0 24px currentColor;
}

.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 24px;
  margin: 24px 0;
  position: relative;
}
.card::before {
  content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%;
  background: linear-gradient(180deg, var(--cyan), transparent);
  border-radius: 6px 0 0 6px;
}
.card h2 {
  color: var(--cyan); font-size: 14px; letter-spacing: 0.1em;
  text-transform: uppercase; margin-bottom: 12px; font-weight: 600;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
}
.card p { color: var(--text-dim); margin-bottom: 12px; }

.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 18px; }
.meta-grid > div { padding: 8px 0; border-left: 2px solid var(--border-lt); padding-left: 12px; }
.dim { color: var(--text-dim); font-size: 11px; letter-spacing: 0.08em; }
.mono { font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace; }

.kpi-row {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin: 24px 0;
}
.kpi {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; padding: 18px 16px; text-align: center;
  transition: all 0.2s; position: relative; overflow: hidden;
}
.kpi:hover { border-color: var(--cyan); transform: translateY(-2px); box-shadow: 0 4px 16px var(--cyan-glow); }
.kpi.pulse { border-color: var(--crit); animation: pulse-border 2s infinite; }
@keyframes pulse-border {
  0%, 100% { box-shadow: 0 0 0 0 var(--crit); }
  50% { box-shadow: 0 0 0 8px transparent; }
}
.kpi-num { font-size: 36px; font-weight: 700; line-height: 1; font-family: 'JetBrains Mono', monospace; }
.kpi-lbl { color: var(--text-dim); font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; margin-top: 8px; }

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin: 24px 0; }
@media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
.two-col .card { margin: 0; }

.chart-wrap { display: flex; gap: 32px; align-items: center; padding: 20px 0; }
.donut { flex-shrink: 0; filter: drop-shadow(0 0 12px var(--cyan-glow)); }
.legend { flex: 1; display: flex; flex-direction: column; gap: 10px; }
.legend > div { display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--border-lt); }
.legend > div:last-child { border-bottom: none; }
.dot { width: 10px; height: 10px; border-radius: 50%; box-shadow: 0 0 8px currentColor; }
.legend b { margin-left: auto; color: var(--cyan); }

.top-list { display: flex; flex-direction: column; gap: 10px; }
.top-item {
  display: flex; align-items: center; gap: 14px;
  padding: 12px; background: var(--bg-card2); border-radius: 4px;
  border-left: 3px solid var(--border-lt); transition: all 0.2s;
}
.top-item:hover { border-left-color: var(--cyan); transform: translateX(4px); }
.top-num {
  width: 36px; height: 36px; border-radius: 50%; border: 2px solid;
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-family: 'JetBrains Mono', monospace; flex-shrink: 0;
}
.top-info { flex: 1; min-width: 0; }
.top-line { display: flex; gap: 8px; flex-wrap: wrap; }
.top-type { color: var(--text-dim); }
.top-meta { display: flex; gap: 10px; align-items: center; margin-top: 4px; flex-wrap: wrap; }

.bars { display: flex; flex-direction: column; gap: 10px; padding-top: 6px; }
.bar-row { display: grid; grid-template-columns: 200px 1fr 60px; gap: 12px; align-items: center; }
.bar-label { color: var(--text-dim); font-size: 13px; }
.bar-track { background: var(--bg-card2); border-radius: 2px; overflow: hidden; height: 22px; border: 1px solid var(--border); }
.bar-fill { height: 100%; transition: width 1.2s ease-out; background: var(--bajo); position: relative; }
.bar-fill::after {
  content: ''; position: absolute; top: 0; right: 0; bottom: 0; width: 2px;
  background: white; opacity: 0.5;
}
.bar-value { font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--cyan); text-align: center; }

.risk-pill {
  display: inline-block; color: white; padding: 4px 10px;
  border-radius: 3px; font-size: 11px; font-weight: 700;
  letter-spacing: 0.05em; text-transform: uppercase;
  box-shadow: 0 0 8px currentColor;
}

.table-wrap { overflow-x: auto; margin: 0 -8px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; min-width: 1000px; }
th {
  text-align: left; padding: 10px 12px; background: var(--bg-card2);
  color: var(--cyan); font-weight: 600; font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
}
td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
.center { text-align: center; }
.device-row { cursor: pointer; transition: background 0.15s; }
.device-row:hover { background: var(--bg-card2); }
.device-row td { color: var(--text); }
.ip-cell { display: flex; align-items: center; gap: 10px; }
.status-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  box-shadow: 0 0 10px currentColor; animation: blink 2s ease-in-out infinite;
}
@keyframes blink { 50% { opacity: 0.6; } }
.mac { color: var(--text-mut); font-family: 'JetBrains Mono', monospace; font-size: 10px; }

.ports-cell { max-width: 280px; }
.port {
  display: inline-block; padding: 2px 8px; margin: 2px;
  border-radius: 3px; font-family: 'JetBrains Mono', monospace;
  font-size: 11px; font-weight: 600;
}
.port-seguro   { background: #14532d33; color: #4ade80; border: 1px solid #16653433; }
.port-neutro   { background: #1e3a8a33; color: #60a5fa; border: 1px solid #1e40af33; }
.port-revisar  { background: #78350f33; color: #fbbf24; border: 1px solid #92400e33; }
.port-inseguro { background: #7c2d1233; color: #fb923c; border: 1px solid #9a341233; }
.port-critico  { background: #7f1d1d44; color: #f87171; border: 1px solid #991b1b66; box-shadow: 0 0 8px #ef444433; }

.badge-crit { background: var(--crit); color: white; padding: 1px 6px; border-radius: 2px; font-size: 10px; font-weight: 700; margin-left: 4px; }

.device-detail td { padding: 0; background: var(--bg-darkest); }
.detail-box { padding: 20px 24px; border-left: 3px solid var(--cyan); background: var(--bg-dark); }
.detail-section { margin-bottom: 20px; }
.detail-section h4 {
  color: var(--cyan); font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.1em; margin-bottom: 10px; font-family: 'JetBrains Mono', monospace;
}
.chip { display: inline-block; padding: 3px 10px; margin: 2px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 3px; color: var(--text-dim); font-size: 11px; font-family: 'JetBrains Mono', monospace; }
.service-detail {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px;
  padding: 14px; margin-bottom: 10px;
}
.service-head { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
.cls { padding: 2px 8px; border-radius: 2px; font-size: 10px; font-weight: 700; letter-spacing: 0.05em; }
.cls-seguro   { background: #14532d; color: #4ade80; }
.cls-neutro   { background: #1e3a8a; color: #60a5fa; }
.cls-revisar  { background: #78350f; color: #fbbf24; }
.cls-inseguro { background: #7c2d12; color: #fb923c; }
.cls-critico  { background: #7f1d1d; color: #fca5a5; }
.kv { font-size: 12px; padding: 3px 0; }
.kv code { background: var(--bg-darkest); padding: 2px 6px; border-radius: 2px; font-size: 11px; color: var(--cyan); border: 1px solid var(--border); }

.cves-list { margin-top: 10px; }
.cve-item {
  background: var(--bg-darkest); border-left: 3px solid var(--crit);
  padding: 10px 14px; margin: 6px 0; border-radius: 0 4px 4px 0;
}
.cve-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.cve-id { color: var(--cyan); font-weight: 700; text-decoration: none; font-family: 'JetBrains Mono', monospace; }
.cve-id:hover { text-decoration: underline; }
.cvss { color: white; padding: 2px 8px; border-radius: 2px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
.kev-badge {
  background: var(--crit); color: white; padding: 2px 8px;
  border-radius: 2px; font-size: 10px; font-weight: 700;
  animation: pulse-bg 1.6s infinite;
}
@keyframes pulse-bg { 50% { opacity: 0.6; } }
.cve-desc { color: var(--text-dim); font-size: 12px; margin-top: 6px; }

.finding-item {
  background: var(--bg-card2); padding: 10px 14px;
  border-radius: 4px; margin: 6px 0; border-left: 3px solid var(--border-lt);
}
.sev-pill { color: white; padding: 2px 8px; border-radius: 2px; font-size: 10px; font-weight: 700; margin-right: 8px; }
.rec-inline { color: var(--cyan); font-size: 12px; margin-top: 4px; padding-left: 10px; }

.recs-card { background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-card2) 100%); }
.recs { list-style: none; counter-reset: rec; }
.recs li {
  position: relative; padding: 12px 16px 12px 64px;
  margin: 8px 0; background: var(--bg-card2);
  border-left: 3px solid var(--cyan); border-radius: 4px;
  transition: all 0.2s;
}
.recs li:hover { transform: translateX(4px); border-left-width: 5px; padding-left: 62px; }
.rec-num {
  position: absolute; left: 16px; top: 50%; transform: translateY(-50%);
  width: 32px; height: 32px; border-radius: 50%;
  background: var(--bg-darkest); border: 2px solid var(--cyan);
  display: flex; align-items: center; justify-content: center;
  color: var(--cyan); font-weight: 700; font-family: 'JetBrains Mono', monospace; font-size: 12px;
}

footer { padding: 24px 0; border-top: 1px solid var(--border); margin-top: 32px; background: var(--bg-darkest); }
footer .container { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px; }

.pad { padding: 24px; }
.dim.center { text-align: center; }

@media print {
  body { background: white; color: black; }
  .grid-bg { display: none; }
  .device-detail { display: table-row !important; }
  .card, .kpi { break-inside: avoid; }
}
"""
