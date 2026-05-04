"""
===============================================================================
 core/logger.py
 -----------------------------------------------------------------------------
 Sistema de logging centralizado con soporte para 'rich' (colores, paneles,
 progress bars). Si 'rich' no está instalado, degrada a logging estándar.
===============================================================================
"""
import logging
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeElapsedColumn)
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ============================================================================
#  CONSOLA GLOBAL
# ============================================================================
if RICH_AVAILABLE:
    console = Console()
else:
    class _FakeConsole:
        def print(self, *args, **kwargs):
            # Quitamos los tags de rich antes de imprimir
            import re
            out = " ".join(str(a) for a in args)
            out = re.sub(r"\[/?[^\]]+\]", "", out)
            print(out)
        def rule(self, title=""):
            print("-" * 70)
            if title: print(title)
            print("-" * 70)
        def status(self, *args, **kwargs):
            from contextlib import contextmanager
            @contextmanager
            def _ctx(): yield
            return _ctx()
    console = _FakeConsole()


# ============================================================================
#  CONFIGURACIÓN DEL LOGGER
# ============================================================================
def setup_logger(name: str = "audit", level: str = "INFO",
                 log_file: Path | None = None) -> logging.Logger:
    """
    Configura y devuelve un logger.

    Args:
        name: nombre del logger.
        level: nivel (DEBUG, INFO, WARNING, ERROR).
        log_file: si se pasa, duplica todo a este fichero.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    logger.handlers.clear()

    if RICH_AVAILABLE:
        handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            show_time=True,
            show_path=False,
            markup=True,
        )
        fmt = "%(message)s"
    else:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "[%(asctime)s] [%(levelname)s] %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    logger.addHandler(handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)

    return logger


# ============================================================================
#  UTILIDADES DE PRESENTACIÓN
# ============================================================================
def print_banner():
    """Imprime el banner del programa."""
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]SMART HOME SECURITY AUDIT[/bold cyan]\n"
            "[dim]Auditoría de seguridad de una vivienda inteligente[/dim]\n"
            "[dim]Proyecto Final ASIX · M14 PAS · Vedruna Vall Terrassa[/dim]",
            border_style="cyan",
            title="v2.0",
            subtitle="[dim]by CVE + Wi-Fi + Sniffing[/dim]"
        ))
    else:
        print("=" * 70)
        print("  SMART HOME SECURITY AUDIT v2.0")
        print("  Proyecto Final ASIX - M14 PAS")
        print("=" * 70)


def print_section(title: str):
    """Imprime un separador de sección."""
    if RICH_AVAILABLE:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{'=' * 70}\n  {title}\n{'=' * 70}")


def get_progress() -> "Progress | None":
    """Devuelve una instancia de Progress de rich, o None si no está disponible."""
    if not RICH_AVAILABLE:
        return None
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    )


def severity_style(severity: str) -> str:
    """Devuelve el estilo rich para una severidad."""
    return {
        "CRITICA":  "white on red",
        "ALTA":     "red",
        "MEDIA":    "yellow",
        "BAJA":     "green",
        "CRITICO":  "white on red",
        "ALTO":     "red",
        "MEDIO":    "yellow",
        "BAJO":     "green",
        "MÍNIMO":   "dim green",
        "CRITICAL": "white on red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
        "NONE":     "dim",
    }.get(severity.upper(), "white")
