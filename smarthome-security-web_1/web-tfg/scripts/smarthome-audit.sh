#!/bin/bash
# =============================================================
# SmartHome Security Audit Script
# Autor: Guillem Villanueva Monclús
# Proyecto: Proyecto Final ASIX 2025-2026 - Vedruna Vall Terrassa
# Versión: 1.0
# Licencia: MIT
# =============================================================
# Descripción:
#   Script de auditoría básica para redes domésticas. Realiza un
#   análisis inicial de la red local, detecta dispositivos
#   conectados, escanea puertos y genera un informe.
#
# Uso:
#   sudo ./smarthome-audit.sh
#   sudo ./smarthome-audit.sh -v      (modo verbose)
#   sudo ./smarthome-audit.sh -q      (modo silencioso)
#   sudo ./smarthome-audit.sh -h      (ayuda)
#
# Requisitos:
#   - bash 4+
#   - nmap
#   - iproute2 (ip)
#   - arp-scan (opcional, recomendado)
# =============================================================

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Variables globales
VERBOSE=0
QUIET=0
REPORT_DIR="./audit-reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE=""
VERSION="1.0"

# ============ FUNCIONES DE UTILIDAD ============

banner() {
    if [ "$QUIET" -eq 0 ]; then
        echo -e "${CYAN}"
        echo "┌──────────────────────────────────────────────────────────┐"
        echo "│          SmartHome Security Audit · v${VERSION}                 │"
        echo "│       Guillem Villanueva · Proyecto Final ASIX 2026      │"
        echo "└──────────────────────────────────────────────────────────┘"
        echo -e "${NC}"
    fi
}

log_ok() {
    [ "$QUIET" -eq 0 ] && echo -e "${GREEN}[✓]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[OK] $1" >> "$REPORT_FILE"
}

log_info() {
    [ "$QUIET" -eq 0 ] && echo -e "${BLUE}[i]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[INFO] $1" >> "$REPORT_FILE"
}

log_warn() {
    [ "$QUIET" -eq 0 ] && echo -e "${YELLOW}[!]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[WARN] $1" >> "$REPORT_FILE"
}

log_crit() {
    [ "$QUIET" -eq 0 ] && echo -e "${RED}[✗]${NC} $1"
    [ -n "$REPORT_FILE" ] && echo "[CRITICAL] $1" >> "$REPORT_FILE"
}

log_verbose() {
    [ "$VERBOSE" -eq 1 ] && [ "$QUIET" -eq 0 ] && echo -e "${CYAN}[v]${NC} $1"
}

show_help() {
    cat << EOF
SmartHome Security Audit Script v${VERSION}

Uso: sudo $0 [OPCIONES]

OPCIONES:
  -v, --verbose     Modo verbose (más información)
  -q, --quiet       Modo silencioso (solo genera el informe)
  -o, --output DIR  Directorio de salida (por defecto: ./audit-reports)
  -h, --help        Muestra esta ayuda

EJEMPLOS:
  sudo $0
  sudo $0 -v
  sudo $0 -o /tmp/reports

Requiere privilegios root para escaneos completos.
EOF
}

# ============ PARSEO DE ARGUMENTOS ============

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        -o|--output)
            REPORT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
done

# ============ COMPROBACIONES INICIALES ============

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error:${NC} Este script necesita permisos de root para funcionar correctamente."
        echo "Ejecuta: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    local missing=()

    for cmd in nmap ip awk grep; do
        if ! command -v $cmd &> /dev/null; then
            missing+=($cmd)
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error:${NC} Faltan las siguientes dependencias: ${missing[*]}"
        echo "Instálalas con: sudo apt install ${missing[*]}"
        exit 1
    fi
}

setup_report() {
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="${REPORT_DIR}/audit-${TIMESTAMP}.txt"
    HTML_REPORT="${REPORT_DIR}/audit-${TIMESTAMP}.html"

    cat > "$REPORT_FILE" << EOF
=============================================================
  SmartHome Security Audit Report
  Generado: $(date)
  Host: $(hostname)
  Usuario: $(whoami)
=============================================================

EOF
}

# ============ DETECCIÓN DE RED ============

detect_network() {
    log_info "Detectando configuración de red..."

    # Interfaz activa (excluyendo loopback)
    INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
    if [ -z "$INTERFACE" ]; then
        log_crit "No se ha podido detectar una interfaz de red activa."
        exit 1
    fi
    log_ok "Interfaz activa: $INTERFACE"

    # Gateway
    GATEWAY=$(ip route | awk '/default/ {print $3; exit}')
    log_ok "Gateway detectado: $GATEWAY"

    # IP local y red
    LOCAL_IP=$(ip -4 addr show $INTERFACE | awk '/inet / {print $2}' | head -n1)
    NETWORK=$(ip -4 route show dev $INTERFACE | awk '/proto/ {print $1; exit}')
    log_ok "IP local: $LOCAL_IP"
    log_ok "Rango de red: $NETWORK"
}

# ============ ESCANEO DE DISPOSITIVOS ============

scan_devices() {
    log_info "Escaneando dispositivos conectados..."

    if [ -z "$NETWORK" ]; then
        log_warn "No se ha podido determinar el rango de red."
        return
    fi

    # nmap ping scan
    local hosts_file="${REPORT_DIR}/hosts-${TIMESTAMP}.txt"
    nmap -sn "$NETWORK" -oG "$hosts_file" > /dev/null 2>&1

    # Extraer hosts activos
    local count=0
    while IFS= read -r line; do
        local ip=$(echo "$line" | awk '{print $2}')
        local hostname=$(echo "$line" | awk -F'[()]' '{print $2}')
        [ -z "$hostname" ] && hostname="desconocido"
        log_ok "  Dispositivo: $ip ($hostname)"
        ((count++))
    done < <(grep "Status: Up" "$hosts_file")

    log_info "Total dispositivos detectados: $count"
    echo "$count" > /tmp/smarthome-count
}

# ============ ESCANEO DE PUERTOS DEL ROUTER ============

scan_router() {
    log_info "Escaneando el router ($GATEWAY)..."

    local router_scan="${REPORT_DIR}/router-scan-${TIMESTAMP}.txt"
    nmap -F -sV "$GATEWAY" > "$router_scan" 2>&1

    # Detectar puertos críticos abiertos
    local critical_ports=("21" "22" "23" "80" "443" "8080" "8443")
    local found_critical=0

    for port in "${critical_ports[@]}"; do
        if grep -qE "^$port/tcp\s+open" "$router_scan"; then
            local service=$(grep -E "^$port/tcp\s+open" "$router_scan" | awk '{print $3}')
            case $port in
                21)
                    log_crit "Puerto 21 (FTP) abierto en el router. Protocolo sin cifrar."
                    ;;
                23)
                    log_crit "Puerto 23 (Telnet) abierto. Deshabilítalo inmediatamente."
                    ;;
                22)
                    log_warn "Puerto 22 (SSH) expuesto en el router. Revisa la configuración."
                    ;;
                80|8080)
                    log_warn "Panel de administración HTTP expuesto (puerto $port)."
                    ;;
                443|8443)
                    log_info "Panel de administración HTTPS en puerto $port."
                    ;;
            esac
            ((found_critical++))
        fi
    done

    if [ "$found_critical" -eq 0 ]; then
        log_ok "No se han detectado puertos críticos expuestos en el router."
    fi
}

# ============ ANÁLISIS WIFI ============

analyze_wifi() {
    log_info "Analizando configuración WiFi..."

    # Verificar si hay interfaz wireless
    if command -v iwconfig &> /dev/null; then
        local wifi_iface=$(iwconfig 2>/dev/null | grep "IEEE 802.11" | awk '{print $1}' | head -n1)

        if [ -n "$wifi_iface" ]; then
            log_ok "Interfaz WiFi detectada: $wifi_iface"

            # Información de la red actual
            local ssid=$(iwconfig "$wifi_iface" 2>/dev/null | grep -oP 'ESSID:"\K[^"]+')
            if [ -n "$ssid" ]; then
                log_info "  SSID actual: $ssid"

                # Comprobar si el SSID es muy común (diccionario)
                case "$ssid" in
                    MOVISTAR_*|vodafone*|MiFibra-*|JAZZTEL_*|Orange-*)
                        log_warn "  El SSID parece ser el de fábrica. Considera cambiarlo."
                        ;;
                esac
            fi
        else
            log_info "No se ha detectado interfaz WiFi activa."
        fi
    else
        log_verbose "iwconfig no está disponible. Omitiendo análisis WiFi detallado."
    fi
}

# ============ DETECCIÓN DE IOT COMÚN ============

detect_iot() {
    log_info "Buscando dispositivos IoT comunes..."

    local iot_ports=("554" "1883" "5353" "8883" "9999")  # RTSP, MQTT, mDNS, MQTT SSL
    local iot_found=0

    if [ -n "$NETWORK" ]; then
        local iot_scan="${REPORT_DIR}/iot-scan-${TIMESTAMP}.txt"
        nmap -p "$(IFS=,; echo "${iot_ports[*]}")" --open "$NETWORK" > "$iot_scan" 2>&1

        local hosts_with_iot=$(grep -c "Host is up" "$iot_scan")
        if [ "$hosts_with_iot" -gt 0 ]; then
            log_warn "Detectados $hosts_with_iot dispositivos con puertos IoT abiertos."
            log_warn "  Revisa manualmente los dispositivos para asegurar que están protegidos."
        else
            log_ok "No se han detectado puertos IoT comunes expuestos."
        fi
    fi
}

# ============ GENERACIÓN DE INFORME HTML ============

generate_html_report() {
    cat > "$HTML_REPORT" << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>SmartHome Security Audit Report</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #0a1128; color: #e0f2ff; padding: 2rem; }
  .container { max-width: 1000px; margin: 0 auto; background: #132651; padding: 2rem; border-radius: 12px; border: 1px solid #1e3a8a; }
  h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 0.5rem; }
  h2 { color: #00b4d8; margin-top: 2rem; }
  .meta { background: #0d1b3d; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; }
  pre { background: #050914; padding: 1rem; border-radius: 8px; overflow-x: auto; color: #00d4ff; font-size: 0.9rem; }
  .ok { color: #00f5a0; }
  .warn { color: #ffb703; }
  .crit { color: #ef476f; }
  .info { color: #00d4ff; }
  footer { text-align: center; margin-top: 2rem; color: #6b8cae; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="container">
<h1>🛡️ SmartHome Security Audit Report</h1>
<div class="meta">
EOF

    echo "<p><strong>Fecha:</strong> $(date)</p>" >> "$HTML_REPORT"
    echo "<p><strong>Host:</strong> $(hostname)</p>" >> "$HTML_REPORT"
    echo "<p><strong>Red analizada:</strong> $NETWORK</p>" >> "$HTML_REPORT"
    echo "<p><strong>Gateway:</strong> $GATEWAY</p>" >> "$HTML_REPORT"
    echo "</div>" >> "$HTML_REPORT"

    echo "<h2>📋 Resultados</h2><pre>" >> "$HTML_REPORT"
    sed -e 's/\[OK\]/<span class="ok">[OK]<\/span>/g' \
        -e 's/\[INFO\]/<span class="info">[INFO]<\/span>/g' \
        -e 's/\[WARN\]/<span class="warn">[WARN]<\/span>/g' \
        -e 's/\[CRITICAL\]/<span class="crit">[CRITICAL]<\/span>/g' \
        "$REPORT_FILE" >> "$HTML_REPORT"
    echo "</pre>" >> "$HTML_REPORT"

    cat >> "$HTML_REPORT" << 'EOF'
<h2>🔧 Recomendaciones básicas</h2>
<ul>
  <li>Cambia las contraseñas por defecto del router y de los dispositivos IoT.</li>
  <li>Deshabilita WPS y servicios innecesarios (Telnet, FTP).</li>
  <li>Actualiza el firmware del router a la última versión.</li>
  <li>Usa WPA3 si tu router lo soporta; si no, WPA2 con una contraseña fuerte.</li>
  <li>Segmenta tu red: separa los dispositivos IoT del resto mediante VLAN o red de invitados.</li>
  <li>Revisa periódicamente los dispositivos conectados a tu red.</li>
</ul>
<footer>
  Generado por SmartHome Security Audit Script v1.0<br>
  Proyecto Final ASIX - Guillem Villanueva Monclús - 2026
</footer>
</div>
</body>
</html>
EOF

    log_ok "Informe HTML generado: $HTML_REPORT"
}

# ============ FLUJO PRINCIPAL ============

main() {
    banner

    check_root
    check_dependencies
    setup_report

    log_info "Iniciando auditoría de seguridad..."
    echo ""

    detect_network
    echo ""

    scan_devices
    echo ""

    scan_router
    echo ""

    analyze_wifi
    echo ""

    detect_iot
    echo ""

    generate_html_report

    # Resumen final
    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}Auditoría finalizada${NC}"
        echo -e "  📄 Informe TXT:  $REPORT_FILE"
        echo -e "  🌐 Informe HTML: $HTML_REPORT"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}Recuerda:${NC} revisa el informe y aplica las recomendaciones."
        echo -e "${YELLOW}        :${NC} usa este script solo en tu propia red."
        echo ""
    fi
}

main "$@"
