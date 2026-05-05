"""
===============================================================================
 modules/cve_lookup.py
 -----------------------------------------------------------------------------
 Correlación de servicios detectados con vulnerabilidades conocidas (CVE)
 usando la API oficial de la NVD (National Vulnerability Database - NIST).

 ═══════════════════════════════════════════════════════════════════════════
  MARCO TEÓRICO (para la memoria del TFG)
 ═══════════════════════════════════════════════════════════════════════════

 CVE (Common Vulnerabilities and Exposures)
 ------------------------------------------
   Sistema estándar de identificación de vulnerabilidades públicas,
   mantenido por MITRE y el NIST. Cada vulnerabilidad tiene un identificador
   único como "CVE-2021-26855" (año + número secuencial).

 CVSS (Common Vulnerability Scoring System)
 ------------------------------------------
   Estándar abierto para puntuar la severidad de una vulnerabilidad de 0 a 10.
   Actualmente en versión 3.1. Categorías:
     • CRITICAL: 9.0-10.0
     • HIGH:     7.0-8.9
     • MEDIUM:   4.0-6.9
     • LOW:      0.1-3.9

 CPE (Common Platform Enumeration)
 ---------------------------------
   Identificador estandarizado de un producto de software/hardware.
   Formato 2.3: cpe:2.3:{part}:{vendor}:{product}:{version}
   Ejemplo:     cpe:2.3:a:apache:http_server:2.4.41
   Es lo que le pasamos a la NVD API para buscar CVEs de ese producto.

 CWE (Common Weakness Enumeration)
 ---------------------------------
   Categorización del TIPO de debilidad (SQLi=CWE-89, XSS=CWE-79, etc.).

 KEV (Known Exploited Vulnerabilities)
 -------------------------------------
   Catálogo de CISA con CVEs que se EXPLOTAN ACTIVAMENTE. Señal clara
   de que una vulnerabilidad es prioritaria de parchar.

 ═══════════════════════════════════════════════════════════════════════════
  RATE LIMITING DE LA NVD
 ═══════════════════════════════════════════════════════════════════════════
  Sin API key:  5 requests / 30s  →  delay de 6 segundos entre requests
  Con API key: 50 requests / 30s  →  delay de 0.6 segundos entre requests

  Se puede obtener una API key gratuita en:
      https://nvd.nist.gov/developers/request-an-api-key

  Exporta la variable de entorno: export NVD_API_KEY="tu-key-aqui"
 ═══════════════════════════════════════════════════════════════════════════
"""
import json
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import List, Optional, Dict

from core import CVE, Service, Device
from core.config import (NVD_API_KEY, NVD_API_URL, NVD_REQUEST_DELAY,
                          NVD_TIMEOUT, NVD_MAX_RETRIES, CVE_CACHE_DB,
                          CVE_CACHE_TTL_DAYS)


# ============================================================================
#  CACHÉ SQLITE
# ============================================================================
#
# ¿Por qué una caché?
#   1. Las respuestas CVE no cambian minuto a minuto: es estable.
#   2. El rate limit de la NVD es ajustado, cada request sin API key
#      cuesta 6 segundos.
#   3. Si escaneamos 20 dispositivos con 5 servicios cada uno son 100
#      consultas → con caché la segunda auditoría va 100x más rápido.
# ============================================================================

def _init_cache() -> None:
    """Crea la BD y tablas si no existen."""
    CVE_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CVE_CACHE_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cpe_queries (
            cpe TEXT PRIMARY KEY,
            cves_json TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_stats (
            date TEXT PRIMARY KEY,
            requests INTEGER DEFAULT 0,
            cache_hits INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def _get_cached(cpe: str) -> Optional[List[CVE]]:
    """Devuelve CVEs cacheados para ese CPE, o None si no hay o caducó."""
    _init_cache()
    conn = sqlite3.connect(CVE_CACHE_DB)
    cur = conn.cursor()
    cur.execute(
        "SELECT cves_json, fetched_at FROM cpe_queries WHERE cpe = ?", (cpe,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    cves_json, fetched_at = row
    # ¿caducada?
    try:
        fetched = datetime.fromisoformat(fetched_at)
        if datetime.now() - fetched > timedelta(days=CVE_CACHE_TTL_DAYS):
            return None
    except Exception:
        return None
    try:
        return [CVE(**c) for c in json.loads(cves_json)]
    except Exception:
        return None


def _set_cached(cpe: str, cves: List[CVE]) -> None:
    """Guarda en caché la respuesta de un CPE."""
    _init_cache()
    conn = sqlite3.connect(CVE_CACHE_DB)
    cur = conn.cursor()
    data = json.dumps([c.to_dict() for c in cves])
    cur.execute(
        "INSERT OR REPLACE INTO cpe_queries (cpe, cves_json, fetched_at) "
        "VALUES (?, ?, ?)",
        (cpe, data, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def _update_stats(hit: bool) -> None:
    """Actualiza contadores de uso."""
    today = datetime.now().strftime("%Y-%m-%d")
    conn = sqlite3.connect(CVE_CACHE_DB)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO api_stats (date, requests, cache_hits)
        VALUES (?, 0, 0)
        ON CONFLICT(date) DO NOTHING
    """, (today,))
    if hit:
        cur.execute(
            "UPDATE api_stats SET cache_hits = cache_hits + 1 WHERE date = ?",
            (today,))
    else:
        cur.execute(
            "UPDATE api_stats SET requests = requests + 1 WHERE date = ?",
            (today,))
    conn.commit()
    conn.close()


# ============================================================================
#  LLAMADA A LA NVD API
# ============================================================================

class NvdClient:
    """
    Cliente para la NVD API 2.0.

    Aplica rate limiting automáticamente (se respeta el delay obligatorio
    entre requests, con o sin API key).
    """

    def __init__(self, api_key: str = "", logger=None):
        self.api_key = api_key
        self.delay = NVD_REQUEST_DELAY
        self.last_request_time = 0.0
        self.logger = logger

    def _rate_limit(self):
        """Espera lo necesario para respetar el rate limit de la NVD."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def search_by_cpe(self, cpe: str, limit: int = 20) -> List[CVE]:
        """
        Busca CVEs asociados a un CPE concreto.

        Args:
            cpe: string CPE 2.3, ej. 'cpe:2.3:a:apache:http_server:2.4.41:...'
            limit: máximo número de CVEs a devolver (los peores primero).
        """
        # 1. Caché
        cached = _get_cached(cpe)
        if cached is not None:
            _update_stats(hit=True)
            if self.logger:
                self.logger.debug(f"CVE cache HIT para {cpe}")
            return cached[:limit]

        # 2. Llamada a la NVD
        if self.logger:
            self.logger.info(f"Consultando NVD para [dim]{cpe}[/dim]")

        self._rate_limit()
        params = {"cpeName": cpe, "resultsPerPage": str(limit)}
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

        headers = {"User-Agent": "SmartHomeAudit/2.0 (PFC ASIX)"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        cves: List[CVE] = []
        for attempt in range(NVD_MAX_RETRIES):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                cves = self._parse_nvd_response(data)
                break
            except urllib.error.HTTPError as e:
                if e.code == 429:  # rate limit
                    if self.logger:
                        self.logger.warning(
                            f"NVD rate limit alcanzado, esperando {self.delay*2}s")
                    time.sleep(self.delay * 2)
                    continue
                if e.code == 404:
                    if self.logger:
                        self.logger.debug(f"CPE no encontrado en NVD: {cpe}")
                    break
                if self.logger:
                    self.logger.warning(f"HTTP {e.code} de NVD: {e.reason}")
                break
            except urllib.error.URLError as e:
                if self.logger:
                    self.logger.warning(f"Error de red consultando NVD: {e.reason}")
                time.sleep(2)
                continue
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Error parseando respuesta NVD: {e}")
                break

        # 3. Guardar en caché (aunque esté vacío, para no re-consultar)
        _set_cached(cpe, cves)
        _update_stats(hit=False)
        return cves[:limit]

    @staticmethod
    def _parse_nvd_response(data: dict) -> List[CVE]:
        """Convierte la respuesta JSON de la NVD en objetos CVE."""
        cves: List[CVE] = []

        for item in data.get("vulnerabilities", []):
            cv = item.get("cve", {})
            cve_id = cv.get("id", "")
            if not cve_id:
                continue

            # Descripción (preferimos inglés, fallback al primero)
            description = ""
            for d in cv.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and cv.get("descriptions"):
                description = cv["descriptions"][0].get("value", "")

            # CVSS v3.1 preferido, fallback a v3.0 y v2
            score, severity, vector = 0.0, "NONE", ""
            metrics = cv.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    score = m.get("baseScore", 0.0)
                    severity = (m.get("baseSeverity", "")
                                or metrics[key][0].get("baseSeverity", "")
                                or "NONE").upper()
                    vector = m.get("vectorString", "")
                    break

            # CWE
            cwe = ""
            for w in cv.get("weaknesses", []):
                for d in w.get("description", []):
                    if d.get("value", "").startswith("CWE-"):
                        cwe = d["value"]
                        break
                if cwe:
                    break

            # Referencias
            refs = [r.get("url", "") for r in cv.get("references", [])][:5]

            # KEV
            in_kev = cv.get("cisaExploitAdd") is not None

            cves.append(CVE(
                id=cve_id,
                description=description[:400],
                cvss_score=float(score),
                cvss_severity=severity or _severity_from_score(float(score)),
                cvss_vector=vector,
                cwe=cwe,
                published=cv.get("published", "")[:10],
                references=refs,
                in_kev=in_kev,
            ))

        # Ordenar por severidad descendente
        cves.sort(key=lambda c: -c.cvss_score)
        return cves


def _severity_from_score(score: float) -> str:
    """Convierte un score CVSS a categoría."""
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score > 0:     return "LOW"
    return "NONE"


# ============================================================================
#  ORQUESTADOR
# ============================================================================

def enrich_with_cves(devices: List[Device], logger=None,
                      max_cves_per_service: int = 10) -> Dict[str, int]:
    """
    Enriquecer todos los dispositivos con sus CVEs.

    Para cada servicio con CPE conocido, consulta la NVD y rellena
    service.cves con los CVEs aplicables.

    Returns:
        Estadísticas: {total_services_scanned, total_cves_found,
                       critical, high, medium, low}
    """
    client = NvdClient(api_key=NVD_API_KEY, logger=logger)
    stats = {"services_scanned": 0, "services_with_cpe": 0,
             "total_cves": 0, "critical": 0, "high": 0,
             "medium": 0, "low": 0}

    # Recopilamos servicios únicos por CPE para no consultar el mismo dos veces
    cpe_to_services: Dict[str, List[Service]] = {}
    for device in devices:
        for service in device.services.values():
            stats["services_scanned"] += 1
            if service.cpe:
                stats["services_with_cpe"] += 1
                cpe_to_services.setdefault(service.cpe, []).append(service)

    if not cpe_to_services:
        if logger:
            logger.warning("No se ha podido generar ningún CPE de los "
                           "servicios detectados. No se consultará la NVD.")
        return stats

    if logger:
        logger.info(f"Consultando NVD para {len(cpe_to_services)} CPEs únicos "
                    f"(caché TTL {CVE_CACHE_TTL_DAYS} días)")

    # Consulta cada CPE y asigna los CVEs a todos los servicios que comparten ese CPE
    for cpe, services_list in cpe_to_services.items():
        cves = client.search_by_cpe(cpe, limit=max_cves_per_service)
        for service in services_list:
            service.cves = cves
            stats["total_cves"] += len(cves)
            for c in cves:
                key = c.cvss_severity.lower()
                if key in stats:
                    stats[key] += 1

    if logger:
        logger.info(f"[green]CVE lookup completado:[/green] "
                    f"{stats['total_cves']} CVEs encontrados "
                    f"(críticos: {stats['critical']}, altos: {stats['high']}, "
                    f"medios: {stats['medium']}, bajos: {stats['low']})")
    return stats


# ============================================================================
#  INTEGRACIÓN CON EL SISTEMA DE HALLAZGOS
# ============================================================================

def cves_to_findings(device: Device) -> None:
    """
    Convierte los CVEs encontrados en Finding objects añadidos al dispositivo.
    Un finding por CVE crítico/alto, para que aparezcan en el informe.
    """
    from core import Finding

    for service in device.services.values():
        for cve in service.cves:
            if cve.cvss_severity not in ("CRITICAL", "HIGH"):
                continue  # solo críticos/altos para no saturar
            severity_map = {"CRITICAL": "CRITICA", "HIGH": "ALTA"}
            kev_note = " [EXPLOTADO ACTIVAMENTE - catálogo CISA KEV]" if cve.in_kev else ""
            device.findings.append(Finding(
                severity=severity_map[cve.cvss_severity],
                category="cve",
                title=f"{cve.id} en {service.product} {service.version}",
                description=f"CVSS {cve.cvss_score} ({cve.cvss_severity}) "
                            f"- {cve.description[:200]}{kev_note}",
                reference=cve.id,
                cvss_score=cve.cvss_score,
                recommendation=f"Actualizar {service.product} a la última "
                               f"versión estable. Ver: {cve.url}"
            ))


# ============================================================================
#  ESTADÍSTICAS DE USO
# ============================================================================
def get_cache_stats() -> dict:
    """Devuelve estadísticas de uso de la caché."""
    _init_cache()
    conn = sqlite3.connect(CVE_CACHE_DB)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cpe_queries")
    total_cached = cur.fetchone()[0]
    cur.execute("SELECT SUM(requests), SUM(cache_hits) FROM api_stats")
    req, hits = cur.fetchone()
    conn.close()
    req = req or 0
    hits = hits or 0
    hit_rate = (hits / (req + hits) * 100) if (req + hits) else 0
    return {
        "total_cpes_cached": total_cached,
        "api_requests_lifetime": req,
        "cache_hits_lifetime": hits,
        "hit_rate_pct": round(hit_rate, 1),
    }
