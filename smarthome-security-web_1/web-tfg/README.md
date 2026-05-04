# SmartHome Security · Web del Proyecto Final

Web de apoyo para el Proyecto Final del grado superior de ASIX: **Auditoría de seguridad de una vivienda inteligente en un entorno doméstico**.

Tecnologías: HTML5 + CSS3 + JavaScript vanilla. Sin frameworks ni dependencias externas. Se puede desplegar en cualquier hosting estático gratuito.

## 📁 Estructura

```
web-tfg/
├── index.html           # Página principal
├── blog.html            # Blog con 15 noticias reales y enlaces verificados
├── scripts.html         # Descarga de scripts
├── about.html           # Sobre el proyecto
├── README.md            # Este archivo
├── css/
│   └── styles.css       # Todos los estilos
├── js/
│   └── script.js        # Interactividad
└── scripts/
    ├── smarthome-audit.sh        # Script de auditoría (Linux)
    └── smarthome-audit-linux.zip # ZIP listo para descargar
```

## ✨ Cambios respecto a la versión anterior

- Todas las menciones a "TFG" se han cambiado por **"Proyecto Final"**.
- El apartado de Agradecimientos del about ha sido **eliminado**.
- Las **15 noticias del blog** ahora enlazan a fuentes reales y verificadas:
  - **INCIBE** (varias entradas oficiales)
  - **The Hacker News**, **WeLiveSecurity (ESET)**, **Cloudflare**, **Kaspersky**
  - **Redes Telecom**, **Infobae**, **RedesZone**, **Infoteknico**
  - **HoyTech**, **Tecnek**, **Revista Ciberseguridad**
- El script ahora se entrega en **ZIP** (`smarthome-audit-linux.zip`), de modo que al descargar no se abre el código en el navegador. El usuario lo descomprime y obtiene el `.sh` con los permisos correctos.

## 🚀 Cómo probarla localmente

### Opción 1: Abrir directamente
Doble clic en `index.html` y se abrirá en el navegador.

### Opción 2: Servidor local (recomendado)
```bash
cd web-tfg
python3 -m http.server 8000
# o
npx serve
```
Abre `http://localhost:8000` en el navegador.

## 🌐 Cómo desplegarla online (gratis)

### GitHub Pages
1. Crea un repositorio en GitHub.
2. Sube todos los archivos.
3. Settings → Pages → Source: `main`/`/root` → Save.
4. La URL será `https://tu-usuario.github.io/nombre-repo/`.

### Netlify (la más fácil)
1. Ve a [netlify.com](https://www.netlify.com/).
2. Arrastra la carpeta `web-tfg` al área de "Deploy".
3. Listo, te da una URL pública en segundos.

## 📰 Noticias del blog (todas verificadas)

| # | Título | Fuente |
|---|--------|--------|
| 1 | Múltiples vulnerabilidades en cámara TriVision NC227WF | INCIBE-CERT |
| 2 | Murdoc_Botnet: campaña Mirai en cámaras AVTech y routers Huawei | Revista Ciberseguridad |
| 3 | Vulnerabilidades históricas en cámaras IP en 2025 | Infoteknico |
| 4 | 5 configuraciones clave del router WiFi para 2026 | Infobae |
| 5 | WPA3: el protocolo de seguridad para tu router | INCIBE |
| 6 | Robo en una smart-home | INCIBE |
| 7 | Variante Mirai "Nexcorium" explota CVE-2024-3721 | The Hacker News |
| 8 | Botnet Mirai: ¿pueden atacarnos nuestros electrodomésticos? | WeLiveSecurity (ESET) |
| 9 | Múltiples vulnerabilidades en cámaras PTZOptics | INCIBE-CERT |
| 10 | Seguridad WiFi en 2025: guía definitiva | HoyTech |
| 11 | Botnet Mirai: una nueva amenaza de más de 1 Tbps | Tecnek |
| 12 | Cómo proteger tu hogar inteligente | Kaspersky |
| 13 | "Ataque al vecino más cercano": nueva técnica WiFi | RedesZone |
| 14 | WPA3: la mayor actualización en redes Wi-Fi de la última década | INCIBE |
| 15 | ¿Qué es la botnet Mirai? | Cloudflare |

Y la **noticia destacada**: "Los hogares conectados sufren una media de 29 ataques IoT al día" (Redes Telecom, basado en informe Bitdefender).

## ✏️ Cómo personalizarla

### Cambiar colores del tema
Variables CSS al principio de `css/styles.css`:
```css
:root {
  --accent-primary: #00d4ff;
  --accent-secondary: #0077b6;
  --bg-primary: #0a1128;
}
```

### Añadir más posts al blog
Duplica un `<a class="blog-row">` en `blog.html` y cambia `href`, `data-category`, emoji, fecha, fuente, título y descripción.

### Añadir el script de Windows (cuando lo tengas)
1. Comprime tu `.ps1` en `scripts/smarthome-audit-windows.zip`.
2. En `scripts.html`, en la tarjeta de Windows:
   - Borra `<span class="coming-soon-badge">Próximamente</span>`.
   - Cambia el botón:
     ```html
     <a href="scripts/smarthome-audit-windows.zip" download class="download-btn">
       ⬇️ Descargar (ZIP)
     </a>
     ```

## 🎨 Detalles técnicos

- **Responsive completo** (móvil, tablet, desktop)
- **Sin dependencias**: vanilla, carga instantánea
- **Animaciones suaves** al hacer scroll (IntersectionObserver)
- **Contadores animados** en estadísticas (maneja decimales y sufijos)
- **Filtros funcionales** en el blog por categorías
- **Easter egg** en la consola del navegador (F12)
- **SEO básico**: meta descriptions, títulos descriptivos

## 💡 Para la presentación

Como vas a presentarla ante 3 profesores:

1. **Despliégala online unos días antes** (GitHub Pages o Netlify).
2. **Prueba la web en el ordenador donde presentarás**.
3. **Demuestra el script en vivo** si puedes: ejecutarlo en tu Kali y enseñar el informe HTML que genera.
4. **Abre algún enlace del blog en directo** si los profes hacen preguntas: todos los enlaces funcionan y llevan a noticias reales (INCIBE, ESET, Kaspersky, etc.).
5. **La terminal simulada** en `scripts.html` queda muy bien visualmente.
6. **F12 al final** para enseñar el mensaje en consola, da un toque profesional.

## 📝 Licencia

MIT. Modificable y reutilizable libremente.

---

**Autor:** Guillem Villanueva Monclús
**Proyecto Final:** ASIX 2025-2026
**Centro:** Vedruna Vall · Terrassa
