"""Núcleo de la suite: config, logging, modelos y utilidades compartidas."""
from .config import (COMMON_PORTS, IOT_FINGERPRINTS, CPE_MAPPINGS,
                     SCAN_PROFILES, RISK, PROJECT_ROOT, REPORTS_DIR,
                     DATA_DIR, CACHE_DIR, NVD_API_KEY)
from .logger import (setup_logger, console, print_banner, print_section,
                     get_progress, severity_style, RICH_AVAILABLE)
from .utils import (is_root, check_command, run_command,
                    get_default_interface, get_local_ip, get_public_ip,
                    is_valid_cidr, normalize_mac, format_duration, sort_ips)
from .models import (Finding, CVE, Service, Device, AuditMeta, AuditReport)

__all__ = [
    "COMMON_PORTS", "IOT_FINGERPRINTS", "CPE_MAPPINGS", "SCAN_PROFILES",
    "RISK", "PROJECT_ROOT", "REPORTS_DIR", "DATA_DIR", "CACHE_DIR",
    "NVD_API_KEY",
    "setup_logger", "console", "print_banner", "print_section",
    "get_progress", "severity_style", "RICH_AVAILABLE",
    "is_root", "check_command", "run_command", "get_default_interface",
    "get_local_ip", "get_public_ip", "is_valid_cidr", "normalize_mac",
    "format_duration", "sort_ips",
    "Finding", "CVE", "Service", "Device", "AuditMeta", "AuditReport",
]
