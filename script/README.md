# Smart Home Security Audit v2.0

Suite modular de auditoría de ciberseguridad para redes domésticas con dispositivos IoT.

**Proyecto Final de Grado Superior ASIX** · Módulo 14 (PAS) · Vedruna Vall Terrassa

---

## 📋 Qué hace

Analiza de forma automatizada toda una red doméstica con dispositivos IoT ("smart home") y genera un informe técnico con:

- **Inventario completo** de dispositivos (IP, MAC, fabricante, tipo, SO).
- **Mapeo de servicios** expuestos por cada dispositivo.
- **Correlación con CVEs reales** consultando la base de datos oficial del NIST (NVD API 2.0).
- **Detección de vulnerabilidades activamente explotadas** (catálogo CISA KEV).
- **Análisis de protocolos inseguros** (Telnet, FTP, HTTP, SMB, UPnP, MQTT sin TLS...).
- **Scoring de riesgo** por dispositivo y global (metodología propia basada en CVSS).
- **Informe profesional** en JSON / TXT / HTML interactivo.

## 🏗️ Arquitectura

```
smart_home_audit/
├── main.py                        # Orquestador principal
├── requirements.txt
├── README.md
│
├── core/                          # Núcleo compartido
│   ├── config.py                  # Configuración centralizada
│   ├── logger.py                  # Logging con rich
│   ├── models.py                  # Dataclasses (Device, Service, CVE, ...)
│   └── utils.py                   # Utilidades compartidas
│
├── modules/                       # Módulos funcionales
│   ├── discovery.py               # Descubrimiento (ping, ARP, arp-scan)
│   ├── portscan.py                # Escaneo TCP + banner grabbing
│   ├── fingerprint.py             # Identificación de dispositivos (OUI, hostname, puertos)
│   ├── cve_lookup.py              # ⭐ Correlación CVE con NVD API + caché SQLite
│   ├── scoring.py                 # Cálculo de riesgo y conclusiones
│   └── reporting.py               # Generación JSON/TXT/HTML
│
├── data/                          # Datos persistentes
│   └── cache/
│       └── cve_cache.db           # Caché SQLite de consultas NVD
│
└── reports/                       # Informes generados
```

## ⚙️ Instalación

### 1. Clonar / copiar el proyecto

```bash
# Si usas git
git clone <tu-repo> smart_home_audit
cd smart_home_audit

# O copia los archivos directamente
```

### 2. Instalar dependencias (opcional pero recomendado)

```bash
pip install -r requirements.txt
```

### 3. Instalar herramientas del sistema recomendadas

```bash
# Debian / Ubuntu / Kali
sudo apt update
sudo apt install arp-scan nmap -y
```

### 4. (MUY RECOMENDADO) Obtener una API Key gratuita de NVD

Sin API key: 5 requests cada 30 segundos (6s entre consultas). Con API key: 50 requests cada 30 segundos (0.6s entre consultas). **En una red con 15-20 dispositivos la diferencia es enorme.**

1. Solicítala aquí (gratis, llega por email en minutos): https://nvd.nist.gov/developers/request-an-api-key
2. Exporta la variable de entorno:

```bash
export NVD_API_KEY="tu-key-aqui"

# O añádelo a tu .bashrc para que sea permanente
echo 'export NVD_API_KEY="tu-key-aqui"' >> ~/.bashrc
```

## 🚀 Uso

```bash
# Autodetecta la red y escanea
sudo -E python3 main.py

# Rango específico
sudo -E python3 main.py -r 192.168.1.0/24

# Escaneo rápido (sólo puertos críticos)
sudo -E python3 main.py --fast

# Escaneo completo (top 1000 puertos + extras IoT)
sudo -E python3 main.py --full

# Sin consultar CVEs (más rápido, para pruebas)
sudo -E python3 main.py --no-cve

# Directorio de salida personalizado
sudo -E python3 main.py -o ~/mis_informes

# Debug (logs detallados)
sudo -E python3 main.py --debug
```

> **Nota:** Se usa `sudo -E` para que conserve la variable `NVD_API_KEY`.

## 📊 Qué verás

Durante la ejecución, el script muestra progreso en tiempo real con barras, tablas y colores (si tienes `rich` instalado).

Al final genera tres informes:

- **`audit_YYYYMMDD_HHMMSS.json`** - Datos estructurados. Ideal para integraciones.
- **`audit_YYYYMMDD_HHMMSS.txt`** - Informe texto plano. Ideal para leer en terminal.
- **`audit_YYYYMMDD_HHMMSS.html`** - Informe visual interactivo. **Ideal como anexo de la memoria del TFG.**

## 🔬 Marco teórico (para la memoria)

### CVE - Common Vulnerabilities and Exposures
Sistema estándar de identificación de vulnerabilidades públicas, mantenido por MITRE. Cada vulnerabilidad tiene un ID único (`CVE-AÑO-NNNNN`).

### CVSS - Common Vulnerability Scoring System
Puntuación de severidad de 0 a 10:
- **Critical** (9.0-10.0) - Parche inmediato
- **High** (7.0-8.9) - Parche urgente
- **Medium** (4.0-6.9) - Parche en plazo razonable
- **Low** (0.1-3.9) - Revisar

### CPE - Common Platform Enumeration
Identificador estandarizado de productos. Formato: `cpe:2.3:{part}:{vendor}:{product}:{version}`. Ejemplo: `cpe:2.3:a:apache:http_server:2.4.41`.

### CWE - Common Weakness Enumeration
Categorización del *tipo* de debilidad (CWE-89=SQL injection, CWE-79=XSS, etc.).

### KEV - Known Exploited Vulnerabilities
Catálogo de CISA con CVEs que **se están explotando activamente** en el mundo real. Son la máxima prioridad de parcheado.

### NVD - National Vulnerability Database
Base de datos del NIST (U.S. National Institute of Standards and Technology) con todos los CVEs, CVSS, CPE... Es la fuente oficial que usa este script.

## 📏 Metodología de scoring

El *score* de cada dispositivo (0-100) se calcula como:

```
score = Σ(puntos_por_hallazgo) + Σ(puntos_por_CVE) + superficie_ataque
score *= multiplicador_tipo_dispositivo
```

Donde:
- **Puntos por hallazgo**: CRITICA=30, ALTA=15, MEDIA=7, BAJA=2
- **Puntos por CVE (CVSS)**: CRITICAL=25, HIGH=15, MEDIUM=7, LOW=2
- **Bonus KEV**: +10 por cada CVE explotado activamente
- **Superficie de ataque**: 1.5 puntos por puerto abierto (cap a 15)
- **Multiplicador de tipo**: alto=1.3× | medio=1.0× | bajo=0.7×

## ⚖️ Consideraciones legales y éticas

- Esta herramienta está diseñada para auditar **tu propia red**. Escanear redes ajenas sin autorización puede ser delito (Código Penal Español, art. 197 bis).
- No realiza pruebas activas de explotación ni brute force de credenciales.
- No altera ni modifica ninguna configuración de los dispositivos.
- Toda la información obtenida proviene de técnicas pasivas de fingerprinting y de consultas públicas a bases de datos oficiales (NVD).

## 🔮 Próximos módulos (roadmap)

Funcionalidades previstas para próximas versiones (y mencionadas como "Treballs futurs" en la memoria):

- **Módulo Wi-Fi**: detección de redes cercanas, cifrado, WPS activo, evil twins.
- **Módulo Sniffing pasivo**: análisis de tráfico en tiempo real con Scapy, grafo de comunicaciones, detección de dominios sospechosos.
- **Análisis TLS profundo**: cifrados débiles, certificados caducados, Heartbleed, etc.
- **OSINT externo**: correlación con Shodan para ver la superficie de ataque pública.
- **Dashboard web en tiempo real** con Flask + Chart.js.
- **Histórico con diff entre auditorías** para detectar cambios sospechosos.
- **Generación de informe PDF profesional** con gráficos (matplotlib/ReportLab).

## 📝 Licencia

MIT (adaptable según necesidades del proyecto académico).

---

## 📞 Contacto

**Autor:** [Tu nombre]
**Proyecto:** PFC ASIX - M14 PAS
**Institución:** Vedruna Vall Terrassa
**Curso:** 2025-2026
