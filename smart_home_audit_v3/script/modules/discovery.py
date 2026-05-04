"""
===============================================================================
 modules/discovery.py
 -----------------------------------------------------------------------------
 Descubrimiento de hosts en la red local.

 Técnicas empleadas (combinadas para maximizar detección):
   1. Ping sweep en paralelo (ICMP Echo Request)
   2. Lectura de tabla ARP del sistema
   3. arp-scan (si está disponible) - más fiable para IoT que ignoran ICMP

 Fundamento teórico:
   Los dispositivos IoT con frecuencia ignoran ICMP (ping) para "ahorrar
   batería" o por firewall. Sin embargo TODOS los dispositivos que estén
   en la red local responden a ARP porque es necesario para que funcione
   IPv4 en la capa 2. Por eso combinamos ambas técnicas.
===============================================================================
"""
import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from core import (check_command, console, get_progress, run_command,
                  sort_ips)
from core.config import PING_TIMEOUT, PING_WORKERS


def ping_host(ip: str, timeout: int = PING_TIMEOUT) -> bool:
    """Ping ICMP a un host (un paquete, sin bloquear)."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 1,
        )
        return r.returncode == 0
    except Exception:
        return False


def read_arp_table() -> Dict[str, str]:
    """Lee la tabla ARP del sistema. Devuelve {ip: mac}."""
    table = {}
    try:
        out = subprocess.check_output(["ip", "neigh", "show"], text=True)
        for line in out.splitlines():
            m = re.match(r"(\S+)\s+dev\s+\S+\s+lladdr\s+(\S+)", line)
            if m:
                table[m.group(1)] = m.group(2).upper()
    except Exception:
        pass
    return table


def arp_scan(network: str) -> Dict[str, str]:
    """
    Ejecuta arp-scan si está disponible.
    Es la técnica más fiable para descubrir hosts IoT que ignoran ping.
    """
    results = {}
    if not check_command("arp-scan"):
        return results
    try:
        out = subprocess.check_output(
            ["arp-scan", "--localnet", "--quiet", "--ignoredups"],
            text=True, stderr=subprocess.DEVNULL, timeout=120,
        )
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})", line)
            if m:
                results[m.group(1)] = m.group(2).upper()
    except Exception:
        pass
    return results


def resolve_hostname(ip: str) -> str:
    """Resolución inversa DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def discover_hosts(network: str, logger) -> Dict[str, dict]:
    """
    Descubre todos los hosts vivos combinando ping sweep, ARP y arp-scan.

    Returns:
        dict {ip: {"mac": str, "hostname": str}}
    """
    logger.info(f"Iniciando descubrimiento en [bold]{network}[/bold]")

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        logger.error(f"Red inválida: {e}")
        return {}

    targets = [str(h) for h in net.hosts()]
    if len(targets) > 512:
        logger.warning(f"Red muy grande ({len(targets)} IPs). "
                       f"Considera usar un /24.")

    alive = set()

    # 1. Ping sweep en paralelo
    progress = get_progress()
    if progress:
        with progress:
            task = progress.add_task(
                "[cyan]Ping sweep...", total=len(targets))
            with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
                futures = {ex.submit(ping_host, ip): ip for ip in targets}
                for f in as_completed(futures):
                    if f.result():
                        alive.add(futures[f])
                    progress.advance(task)
    else:
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
            futures = {ex.submit(ping_host, ip): ip for ip in targets}
            for f in as_completed(futures):
                if f.result():
                    alive.add(futures[f])

    logger.info(f"Ping sweep: {len(alive)} hosts responden a ICMP")

    # 2. Tabla ARP (hosts que vimos recientemente aunque no respondan a ping)
    arp_map = read_arp_table()
    arp_new = 0
    for ip in arp_map:
        try:
            if ipaddress.ip_address(ip) in net and ip not in alive:
                alive.add(ip)
                arp_new += 1
        except Exception:
            pass
    if arp_new:
        logger.info(f"ARP table: +{arp_new} hosts adicionales")

    # 3. arp-scan (la bomba para IoT)
    if check_command("arp-scan"):
        with console.status("[cyan]Ejecutando arp-scan...", spinner="dots"):
            scan_results = arp_scan(network)
        arp_scan_new = 0
        for ip, mac in scan_results.items():
            try:
                if ipaddress.ip_address(ip) in net:
                    if ip not in alive:
                        arp_scan_new += 1
                    alive.add(ip)
                    arp_map[ip] = mac
            except Exception:
                pass
        if arp_scan_new:
            logger.info(f"arp-scan: +{arp_scan_new} hosts adicionales")
    else:
        logger.warning("arp-scan no está instalado (apt install arp-scan) "
                       "— la detección de IoT puede ser menos fiable")

    # Construir resultado con hostnames
    result = {}
    for ip in sort_ips(list(alive)):
        result[ip] = {
            "mac": arp_map.get(ip, ""),
            "hostname": resolve_hostname(ip),
        }

    logger.info(f"[green]Total: {len(result)} dispositivos detectados[/green]")
    return result
