"""
===============================================================================
 core/models.py
 -----------------------------------------------------------------------------
 Modelos de datos de la suite. Centralizados para que todos los módulos
 hablen el mismo lenguaje.
===============================================================================
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class Finding:
    """Un hallazgo de seguridad concreto."""
    severity: str          # CRITICA / ALTA / MEDIA / BAJA
    category: str          # port / version / config / cve / wifi / traffic
    title: str
    description: str
    reference: str = ""    # CVE-XXXX-YYYY o URL
    cvss_score: float = 0.0
    recommendation: str = ""


@dataclass
class CVE:
    """Representa un CVE obtenido de la NVD."""
    id: str                          # CVE-2021-26855
    description: str
    cvss_score: float = 0.0          # 0-10
    cvss_severity: str = "NONE"      # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cvss_vector: str = ""            # CVSS:3.1/AV:N/AC:L/...
    cwe: str = ""                    # CWE-79, CWE-89...
    published: str = ""              # fecha ISO
    references: List[str] = field(default_factory=list)
    in_kev: bool = False             # Known Exploited Vulnerabilities catalog

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"

    def to_dict(self):
        return asdict(self)


@dataclass
class Service:
    """Un servicio detectado en un puerto."""
    port: int
    protocol: str = "tcp"
    name: str = ""                   # http, ssh, ftp...
    banner: str = ""
    product: str = ""                # apache, openssh, nginx...
    version: str = ""
    cpe: str = ""                    # cpe:2.3:a:vendor:product:version
    classification: str = "REVISAR"  # SEGURO/NEUTRO/REVISAR/INSEGURO/CRITICO
    cves: List[CVE] = field(default_factory=list)


@dataclass
class Device:
    """Un dispositivo detectado en la red."""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: str = "Desconocido"
    type_risk: str = "bajo"          # bajo / medio / alto
    os_guess: str = ""
    services: Dict[int, Service] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "MÍNIMO"       # MÍNIMO/BAJO/MEDIO/ALTO/CRÍTICO

    @property
    def open_ports(self) -> List[int]:
        return sorted(self.services.keys())

    @property
    def total_cves(self) -> int:
        return sum(len(s.cves) for s in self.services.values())

    @property
    def critical_cves(self) -> int:
        return sum(1 for s in self.services.values()
                   for c in s.cves if c.cvss_severity == "CRITICAL")

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "type_risk": self.type_risk,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "services": {str(p): {
                "port": s.port, "protocol": s.protocol, "name": s.name,
                "banner": s.banner, "product": s.product, "version": s.version,
                "cpe": s.cpe, "classification": s.classification,
                "cves": [c.to_dict() for c in s.cves],
            } for p, s in self.services.items()},
            "findings": [asdict(f) for f in self.findings],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_cves": self.total_cves,
            "critical_cves": self.critical_cves,
        }


@dataclass
class AuditMeta:
    """Metadatos de una auditoría."""
    network: str
    interface: str = ""
    gateway: str = ""
    public_ip: str = ""
    timestamp: str = ""
    duration: float = 0.0
    ports_scanned: int = 0
    mode: str = "standard"
    modules_enabled: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class AuditReport:
    """Informe completo de una auditoría."""
    meta: AuditMeta
    devices: List[Device] = field(default_factory=list)
    wifi_networks: List[dict] = field(default_factory=list)
    traffic_summary: dict = field(default_factory=dict)
    conclusions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "meta": asdict(self.meta),
            "devices": [d.to_dict() for d in self.devices],
            "wifi_networks": self.wifi_networks,
            "traffic_summary": self.traffic_summary,
            "conclusions": self.conclusions,
        }
