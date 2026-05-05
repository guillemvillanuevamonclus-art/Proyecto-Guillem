#!/usr/bin/env python3
"""
===============================================================================
 smart_home_audit / main.py
 -----------------------------------------------------------------------------
 Orquestador principal de la suite de auditoría de seguridad doméstica.

 Uso:
   sudo python3 main.py                          # autodetecta red
   sudo python3 main.py -r 192.168.1.0/24        # rango manual
   sudo python3 main.py --fast                   # escaneo rápido
   sudo python3 main.py --full                   # escaneo completo
   sudo python3 main.py --no-cve                 # sin correlación CVE

 Proyecto Final de Grado Superior ASIX - M14 PAS
 Vedruna Vall Terrassa
===============================================================================
"""
import argparse
import sys
import time
from datetime import datetime

from core import (AuditMeta, AuditReport, Device, console,
                  is_root, is_valid_cidr, get_default_interface,
                  get_public_ip, format_duration, setup_logger,
                  print_banner, print_section, RICH_AVAILABLE,
                  REPORTS_DIR, NVD_API_KEY, SCAN_PROFILES)

from modules import discovery, portscan, fingerprint, cve_lookup, scoring, reporting


def parse_args():
    p = argparse.ArgumentParser(
        description="Smart Home Security Audit - Suite de auditoría IoT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Proyecto Final ASIX - M14 PAS - Vedruna Vall Terrassa",
    )
    p.add_argument("-r", "--range", help="Rango CIDR (ej: 192.168.1.0/24). "
                   "Por defecto, autodetecta la red local.")
    p.add_argument("-o", "--output", default=str(REPORTS_DIR),
                   help=f"Directorio de informes (por defecto {REPORTS_DIR})")
    p.add_argument("--fast", action="store_true",
                   help="Escaneo rápido (menos puertos)")
    p.add_argument("--full", action="store_true",
                   help="Escaneo completo (top 1000 + IoT)")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Timeout por puerto en segundos")
    p.add_argument("--no-cve", action="store_true",
                   help="No consultar la NVD (más rápido)")
    p.add_argument("--no-public-ip", action="store_true",
                   help="No consultar la IP pública")
    p.add_argument("--debug", action="store_true", help="Logging verbose")
    return p.parse_args()


def run(args) -> int:
    print_banner()
    logger = setup_logger(level="DEBUG" if args.debug else "INFO")

    # =========================================================================
    #  Comprobaciones previas
    # =========================================================================
    if not is_root():
        logger.warning("No se ejecuta como root. Algunas funciones pueden "
                       "no estar disponibles (ARP, puertos <1024).")
    else:
        logger.info("Ejecutando como root ✓")

    if not RICH_AVAILABLE:
        logger.warning("Librería 'rich' no instalada. Salida en modo básico. "
                       "Instala con: pip install rich")

    # =========================================================================
    #  Detectar red
    # =========================================================================
    if args.range:
        if not is_valid_cidr(args.range):
            logger.error(f"CIDR inválido: {args.range}")
            return 2
        network = args.range
        iface = gateway = None
    else:
        iface, gateway, network = get_default_interface()
        if not network:
            logger.error("No se ha podido autodetectar la red. "
                         "Usa -r 192.168.X.0/24")
            return 2

    # IP pública (solo para el informe, útil para mencionar Shodan/superficie externa)
    public_ip = ""
    if not args.no_public_ip:
        with console.status("[cyan]Consultando IP pública..."):
            public_ip = get_public_ip() or ""

    logger.info(f"Interfaz: [bold]{iface or '?'}[/bold] | "
                f"Gateway: [bold]{gateway or '?'}[/bold] | "
                f"Red: [bold]{network}[/bold]")
    if public_ip:
        logger.info(f"IP pública: [bold]{public_ip}[/bold]")

    # =========================================================================
    #  Perfil de escaneo
    # =========================================================================
    if args.fast:
        profile = SCAN_PROFILES["fast"]
        mode = "fast"
    elif args.full:
        profile = SCAN_PROFILES["full"]
        mode = "full"
    else:
        profile = SCAN_PROFILES["standard"]
        mode = "standard"

    ports = profile["ports"]
    timeout = args.timeout or profile["timeout"]
    logger.info(f"Perfil: [bold]{mode}[/bold] ({len(ports)} puertos por host, "
                f"timeout {timeout}s)")

    if NVD_API_KEY:
        logger.info("API Key NVD: [green]configurada ✓[/green] "
                    "(rate limit: 50 req/30s)")
    else:
        logger.info("API Key NVD: [yellow]no configurada[/yellow] "
                    "(rate limit: 5 req/30s - más lento)")

    modules_enabled = ["discovery", "portscan", "fingerprint", "scoring", "reporting"]
    if not args.no_cve:
        modules_enabled.append("cve_lookup")

    # =========================================================================
    #  Fase 1: Descubrimiento
    # =========================================================================
    t_start = time.time()
    print_section("FASE 1: Descubrimiento de dispositivos")
    hosts = discovery.discover_hosts(network, logger)
    if not hosts:
        logger.error("No se ha detectado ningún dispositivo.")
        return 0

    # =========================================================================
    #  Fase 2: Escaneo de puertos + banner grabbing
    # =========================================================================
    print_section("FASE 2: Escaneo de puertos y servicios")
    devices = []
    from core import get_progress
    progress = get_progress()

    if progress:
        with progress:
            task = progress.add_task(
                f"[cyan]Escaneando {len(hosts)} hosts...",
                total=len(hosts))
            for ip, info in hosts.items():
                services = portscan.scan_services(ip, ports, timeout=timeout)
                device = Device(
                    ip=ip, mac=info["mac"], hostname=info["hostname"],
                    services=services,
                )
                devices.append(device)
                progress.advance(task)
    else:
        for i, (ip, info) in enumerate(hosts.items(), 1):
            logger.info(f"[{i}/{len(hosts)}] Escaneando {ip}...")
            services = portscan.scan_services(ip, ports, timeout=timeout)
            device = Device(
                ip=ip, mac=info["mac"], hostname=info["hostname"],
                services=services,
            )
            devices.append(device)

    total_services = sum(len(d.services) for d in devices)
    logger.info(f"Escaneo completado: {total_services} servicios detectados "
                f"en {len(devices)} dispositivos")

    # =========================================================================
    #  Fase 3: Fingerprinting
    # =========================================================================
    print_section("FASE 3: Identificación de dispositivos")
    for device in devices:
        fingerprint.fingerprint_device(device)
        device.os_guess = fingerprint.guess_os(device)

    # Resumen de tipos detectados
    type_counts = {}
    for d in devices:
        type_counts[d.device_type] = type_counts.get(d.device_type, 0) + 1
    logger.info(f"Tipos de dispositivos detectados: " +
                ", ".join(f"{t}({n})" for t, n in
                          sorted(type_counts.items(), key=lambda x: -x[1])))

    # Analizar servicios (Findings básicos por puerto/banner)
    for device in devices:
        for service in device.services.values():
            device.findings.extend(portscan.analyze_service(service))

    # =========================================================================
    #  Fase 4: Correlación CVE (NVD)
    # =========================================================================
    if not args.no_cve:
        print_section("FASE 4: Correlación con vulnerabilidades (NVD)")
        cves_with_cpe = sum(1 for d in devices for s in d.services.values() if s.cpe)
        if cves_with_cpe == 0:
            logger.warning("No hay servicios con CPE detectado. "
                           "Saltando consulta NVD.")
        else:
            logger.info(f"Consultando CVEs para {cves_with_cpe} servicios "
                        f"con CPE identificado...")
            cve_stats = cve_lookup.enrich_with_cves(devices, logger)
            # Convertir CVEs en Findings
            for device in devices:
                cve_lookup.cves_to_findings(device)

            # Mostrar stats de caché
            cache_stats = cve_lookup.get_cache_stats()
            logger.info(f"Caché CVE: {cache_stats['total_cpes_cached']} CPEs "
                        f"almacenados, hit-rate "
                        f"{cache_stats['hit_rate_pct']}%")
    else:
        logger.info("Módulo CVE desactivado (--no-cve)")

    # =========================================================================
    #  Fase 5: Scoring
    # =========================================================================
    print_section("FASE 5: Evaluación de riesgo")
    scoring.apply_scoring(devices)

    critical = [d for d in devices if d.risk_level == "CRÍTICO"]
    high = [d for d in devices if d.risk_level == "ALTO"]
    if critical:
        logger.warning(f"[red]{len(critical)} dispositivos en estado CRÍTICO[/red]")
        for d in critical:
            logger.warning(f"  • {d.ip} ({d.device_type}) - "
                           f"score {d.risk_score}, {d.total_cves} CVEs")
    if high:
        logger.warning(f"[yellow]{len(high)} dispositivos con riesgo ALTO[/yellow]")

    # =========================================================================
    #  Fase 6: Conclusiones y reporting
    # =========================================================================
    print_section("FASE 6: Generación de informes")
    duration = time.time() - t_start

    meta = AuditMeta(
        network=network,
        interface=iface or "",
        gateway=gateway or "",
        public_ip=public_ip,
        duration=duration,
        ports_scanned=len(ports),
        mode=mode,
        modules_enabled=modules_enabled,
    )

    conclusions = scoring.build_conclusions(devices, meta)
    report = AuditReport(meta=meta, devices=devices, conclusions=conclusions)

    from pathlib import Path
    json_path, txt_path, html_path = reporting.save_all_reports(
        report, Path(args.output))

    # =========================================================================
    #  Resumen final
    # =========================================================================
    print_section("AUDITORÍA COMPLETADA")
    logger.info(f"Duración total: {format_duration(duration)}")
    logger.info(f"Riesgo global: [bold]{conclusions['resumen']['riesgo_global']}[/bold] "
                f"(score medio {conclusions['resumen']['score_medio']})")
    logger.info(f"Dispositivos: {len(devices)} | "
                f"Críticos: {len(critical)} | Altos: {len(high)} | "
                f"CVEs: {sum(d.total_cves for d in devices)}")

    console.print()
    console.print(f"[green]✓ Informes guardados:[/green]")
    console.print(f"  • JSON: {json_path}")
    console.print(f"  • TXT:  {txt_path}")
    console.print(f"  • HTML: [bold]{html_path}[/bold]")
    console.print()
    console.print(f"[dim]Abre el HTML en tu navegador: "
                  f"firefox {html_path}[/dim]")
    console.print()

    return 0


def main():
    args = parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Auditoría interrumpida por el usuario.[/yellow]")
        return 130
    except Exception as e:
        console.print(f"\n[red]Error fatal: {e}[/red]")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
