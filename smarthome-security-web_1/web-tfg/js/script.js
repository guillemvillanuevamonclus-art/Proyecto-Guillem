// ============================================
// SmartHome Security - JS Principal
// ============================================

// ============ MENÚ HAMBURGUESA ============
const menuToggle = document.querySelector('.menu-toggle');
const navLinks = document.querySelector('.nav-links');

if (menuToggle) {
    menuToggle.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        menuToggle.textContent = navLinks.classList.contains('active') ? '✕' : '☰';
    });
}

// ============ FADE IN AL HACER SCROLL ============
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('fade-in');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

document.querySelectorAll('.card, .blog-card, .script-card, .timeline-item, .stat-item').forEach(el => {
    observer.observe(el);
});

// ============ CONTADOR ANIMADO EN STATS ============
const counters = document.querySelectorAll('[data-count]');

const animateCounter = (el) => {
    const target = parseFloat(el.getAttribute('data-count'));
    const originalText = el.textContent;
    // Extraer el prefijo (+, -) y sufijo (%, B, Tbps, etc.)
    const match = originalText.match(/^([+\-]?)([\d.,]+)(.*)$/);
    const prefix = match ? match[1] : '';
    const suffix = match ? match[3] : '';
    const hasDecimals = target % 1 !== 0;
    const duration = 2000;
    const steps = 60;
    const stepValue = target / steps;
    let current = 0;
    let stepCount = 0;

    const update = () => {
        stepCount++;
        current = stepValue * stepCount;
        if (stepCount >= steps) {
            const finalValue = hasDecimals ? target.toFixed(2) : target.toString();
            el.textContent = prefix + finalValue + suffix;
        } else {
            const displayValue = hasDecimals ? current.toFixed(2) : Math.floor(current).toString();
            el.textContent = prefix + displayValue + suffix;
            setTimeout(update, duration / steps);
        }
    };
    update();
};

const counterObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            animateCounter(entry.target);
            counterObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });

counters.forEach(counter => counterObserver.observe(counter));

// ============ FILTROS DEL BLOG ============
// Soporta tanto las antiguas .filter-btn y .blog-card como las nuevas .filter-chip y .blog-row
const filterBtns = document.querySelectorAll('.filter-chip, .filter-btn');
const blogItems = document.querySelectorAll('.blog-row[data-category], .blog-card[data-category]');

// Inicializar transiciones
blogItems.forEach(item => {
    item.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
});

filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        // Quitar active de todos y añadirlo al clicado
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const filter = btn.getAttribute('data-filter');
        let visibleCount = 0;

        blogItems.forEach(item => {
            const category = item.getAttribute('data-category');
            if (filter === 'all' || filter === category) {
                item.style.display = '';
                setTimeout(() => {
                    item.style.opacity = '1';
                    item.style.transform = 'translateY(0)';
                }, 50);
                visibleCount++;
            } else {
                item.style.opacity = '0';
                item.style.transform = 'translateY(20px)';
                setTimeout(() => {
                    item.style.display = 'none';
                }, 300);
            }
        });

        // Mensaje si no hay resultados
        const blogGrid = document.getElementById('blog-grid');
        if (blogGrid) {
            let emptyMsg = document.getElementById('empty-filter-msg');
            if (visibleCount === 0) {
                if (!emptyMsg) {
                    emptyMsg = document.createElement('div');
                    emptyMsg.id = 'empty-filter-msg';
                    emptyMsg.style.cssText = 'text-align: center; padding: 3rem; color: var(--text-muted); grid-column: 1/-1;';
                    emptyMsg.innerHTML = '<p style="font-size: 3rem; margin-bottom: 1rem;">🔍</p><p>No hay artículos en esta categoría todavía.</p>';
                    blogGrid.appendChild(emptyMsg);
                }
            } else if (emptyMsg) {
                emptyMsg.remove();
            }
        }
    });
});

// ============ CARGAR MÁS (simulado) ============
const loadMoreBtn = document.getElementById('load-more');
if (loadMoreBtn) {
    loadMoreBtn.addEventListener('click', () => {
        loadMoreBtn.textContent = '✓ No hay más artículos disponibles';
        loadMoreBtn.disabled = true;
        loadMoreBtn.style.opacity = '0.6';
        loadMoreBtn.style.cursor = 'not-allowed';
    });
}

// ============ SCROLL SUAVE PARA ANCLAS ============
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        const href = this.getAttribute('href');
        if (href !== '#' && href.length > 1) {
            e.preventDefault();
            const target = document.querySelector(href);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    });
});

// ============ NAVBAR ON SCROLL ============
let lastScroll = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', () => {
    const currentScroll = window.pageYOffset;

    if (currentScroll > 100) {
        navbar.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.3)';
    } else {
        navbar.style.boxShadow = 'none';
    }

    lastScroll = currentScroll;
});

// ============ EFECTO DE TECLEO EN HERO (opcional) ============
// Se puede activar descomentando esta sección si se quiere un efecto "hacker"
/*
const heroTitle = document.querySelector('.hero h1');
if (heroTitle) {
    const text = heroTitle.textContent;
    heroTitle.textContent = '';
    let i = 0;
    const type = () => {
        if (i < text.length) {
            heroTitle.textContent += text.charAt(i);
            i++;
            setTimeout(type, 50);
        }
    };
    type();
}
*/

// ============ MENSAJE DE BIENVENIDA EN CONSOLA ============
console.log('%c🛡️ SmartHome Security', 'color: #00d4ff; font-size: 24px; font-weight: bold;');
console.log('%cProyecto TFG · Guillem Villanueva Monclús', 'color: #a8c5e0; font-size: 14px;');
console.log('%cASIX 2025-2026 · Vedruna Vall Terrassa', 'color: #6b8cae; font-size: 12px;');
console.log('%c¿Eres curioso? Hay cosas más interesantes que la consola ;)', 'color: #00f5a0; font-size: 12px; font-style: italic;');
