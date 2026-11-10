#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
seeds/xss_challenge.py
----------------------
Reto Web Cross-Site Scripting (Combo #1 Auto-click Admin + #4 Bypass de Filtro .replace):
  👨‍🏫 "El 4.99 de Don Severo (Edición Bodas de Oro)"
  Jornadas InnoSoft — 50º Aniversario de los Estudios de Informática (ETSII)

Este archivo es 100% autónomo (todo en uno, sin ningún archivo extra):
  1. Actúa como seed de CTFd (basado en TEMPLATE_challenge.py) insertando el reto,
     la flag, las pistas, las etiquetas y la solución.
  2. Registra automáticamente la aplicación interactiva del reto como una Página
     interna de CTFd en la ruta `/don-severo` (y `/don-severo/`), funcionando
     directamente en `http://localhost:8000/don-severo` y dentro del túnel de
     Cloudflare de vuestro dominio sin tocar Nginx ni abrir puertos extra.
  3. Además incluye un servidor HTTP autónomo (`--serve` en el puerto 5004) por si
     se desea probar de forma independiente fuera de CTFd.
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SEEDS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SEEDS_DIR, ".."))

# ── ← EDITAR ──────────────────────────────────────────────────────────────────
# Clave única en snake_case — debe coincidir con la entrada en config.yml / config.json
CONFIG_KEY = "xss_challenge"
# ──────────────────────────────────────────────────────────────────────────────

CHALLENGE_PORT = int(os.environ.get("XSS_CHALLENGE_PORT", "5004"))
CHALLENGE_ROUTE = "don-severo"


def load_config() -> dict:
    config_path = os.path.join(SEEDS_DIR, "config.json")
    if not os.path.exists(config_path):
        return {"enabled": True, "state": "visible"}
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("challenges", {}).get(CONFIG_KEY, {"enabled": True, "state": "visible"})


# ==============================================================================
# ← EDITAR: datos del reto (CTFd)
# ==============================================================================

CHALLENGE_NAME        = "El 4.99 de Don Severo"
CHALLENGE_CATEGORY    = "Web"
CHALLENGE_VALUE       = 150
CHALLENGE_ATTRIBUTION = "InnoSoft Days — 50º Aniversario ETSII"

CHALLENGE_DESCRIPTION = """\
## 👨‍🏫 El 4.99 de Don Severo (Edición Bodas de Oro)

Bienvenido al **Portal Automatizado de Lloros y Revisiones v1.976** del ilustrísimo Catedrático **Don Severo**.

Don Severo lleva dando clase en la escuela desde que se inauguraron los estudios de Informática en **1976** (cuando los exámenes se compilaban a ojo mirando al trasluz agujeros en tarjetas perforadas). Te ha dejado la asignatura en un **4.99** y, para colmo, se niega a daros libre para ir a las charlas de las **Jornadas InnoSoft** porque dice que *«las conferencias modernas ablandan el carácter»*.

En la parte superior de su portal hay un **Botón Dorado de Aprobado General**, pero está bloqueado para alumnos y solo responde si lo pulsa el navegador de Don Severo.

### 🎯 Objetivo
Burla el filtro "Anti-Listillos" del buzón de reclamaciones.

### 🌐 Acceso al reto
👉 **[👨‍🏫 Abrir el Portal de Revisión de Don Severo (/don-severo)](/don-severo)**
"""

# La flag exacta que el participante debe enviar
FLAG_CONTENT = "INNOSOFT{d0n_s3v3r0_jub1l4t3_y4_50_4n0s_b4st4n}"
FLAG_TYPE    = "static"   # "static" (exacta) | "regex" (expresión regular)
FLAG_DATA    = ""         # "" = case-sensitive | "case_insensitive"

# Pistas opcionales
HINTS = [
    {
        "title":   "Pista 1",
        "content": (
            "El profesor tiene abierto un proceso de solicitud de lloros para reclamar una subida de nota."
            "¿Has probado a enviar uno? Quizás valore tu creatividad para subirte unos puntos en el examen"
        ),
        "cost":    25,   # cuesta 25 puntos
    },
    {
        "title":   "Pista 2",
        "content": (
            "El profesor ha desarrollado con cortafuegos que impide el uso de cierto tipo de palabras."
            "¿Has probado a intentar maquillarlas de alguna manera?"
        ),
        "cost":    25,
    },
    {
        "title":   "Pista 3",
        "content": (
            "Hay un ejemplo de cómo funciona un botón con código javascript."
            "Quizás si compruebas el nombre que tiene el id del botón (Ctrl+derecho, Inspeccionar), "
            "puedas crear un script con un contenido parecido al del botón."
        ),
        "cost":    50,
    },
]

# Etiquetas para filtrar retos en el panel
TAGS = ["web", "xss", "filter-bypass", "innosoft", "50-aniversario"]

# Writeup/solución (estado "hidden" → solo el admin la ve hasta publicarla)
SOLUTION = """\
## Solución — El 4.99 de Don Severo (XSS + Bypass de Filtro No Recursivo)

### 1. Análisis del problema
Necesitamos que el navegador de `Don_Severo` haga clic en el botón dorado cuando lea nuestra reclamación.
Inspeccionando el elemento en el navegador (DevTools), vemos que su ID es: `comprar-soborno-al-profesor-btn`.

En la propia interfaz tenemos dos ayudas clave:
1. **La Macro de Accesibilidad de Don Severo** nos muestra la sintaxis exacta en JavaScript para pulsar un botón por su ID:
   ```javascript
   document.getElementById('boton-denegar').click()
   ```
   Por tanto, para pulsar el botón dorado necesitamos ejecutar:
   ```javascript
   document.getElementById('comprar-soborno-al-profesor-btn).click()
   ```
2. **El Cortafuegos Artesanal de 1998** elimina `<script>` y `</script>` **una sola vez** (reemplazo no recursivo).

### 2. Construcción del Payload (Anidamiento de etiquetas)
Anidamos `<script>` dentro de sí mismo (`<scr<script>ipt>`) y hacemos lo mismo con el cierre (`</scr</script>ipt>`):
```html
<scr<script>ipt>document.getElementById('comprar-soborno-al-profesor-btn').click()</scr</script>ipt>
```

Al pasar por el filtro de Don Severo, se eliminan las etiquetas centrales y el mensaje resultante que ejecuta el navegador del profesor es:
```html
<script>document.getElementById('comprar-soborno-al-profesor-btn').click()</script>
```

### 3. Flag obtenida
Al enviar la reclamación, el navegador de Don Severo ejecuta el script, pulsa el botón dorado de Aprobado General y revela la flag:
```
INNOSOFT{d0n_s3v3r0_jub1l4t3_y4_50_4n0s_b4st4n}
```
"""


# ==============================================================================
# PÁGINA INTERACTIVA INTEGRADA EN CTFd (/don-severo y /don-severo/)
# ==============================================================================

_XOR_KEY = 69
_ENC_FLAG_JSON = json.dumps([ord(c) ^ _XOR_KEY for c in FLAG_CONTENT])

EMBEDDED_CHALLENGE_PAGE_HTML = r"""
<style>
  .severo-wrap {
    --bg-dark: #0a0d14;
    --bg-panel: #131926;
    --bg-console: #07090e;
    --gold: #f59e0b;
    --gold-light: #fde047;
    --cyan: #38bdf8;
    --green: #22c55e;
    --red: #ef4444;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --border: #283246;
    color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    padding: 16px 0 50px;
  }

  /* Cabecera */
  .severo-header {
    background: linear-gradient(135deg, rgba(239,68,68,0.16), rgba(245,158,11,0.12));
    border: 1px solid rgba(245,158,11,0.5);
    border-radius: 14px;
    padding: 22px 26px;
    margin-bottom: 18px;
    background-color: #0f172a;
    box-shadow: 0 10px 28px rgba(0,0,0,0.35);
  }
  .severo-badge {
    display: inline-block;
    background: linear-gradient(90deg, #f59e0b, #eab308);
    color: #0a0d14;
    font-weight: 800;
    font-size: 0.76rem;
    padding: 4px 12px;
    border-radius: 999px;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .severo-header h1 {
    font-size: 1.7rem;
    color: #fff;
    margin-bottom: 8px;
    font-weight: 800;
  }
  .severo-header h1 span {
    color: var(--gold-light);
  }
  .severo-story {
    color: #cbd5e1;
    font-size: 0.93rem;
    line-height: 1.55;
    margin: 0;
  }
  .severo-story strong {
    color: var(--gold-light);
  }

  /* Panel del Botón Dorado Superior */
  .severo-gold-panel {
    background: linear-gradient(135deg, rgba(245,158,11,0.15), rgba(19,25,38,0.95));
    border: 2px solid var(--gold);
    border-radius: 14px;
    padding: 20px 24px;
    margin-bottom: 22px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    box-shadow: 0 0 30px rgba(245,158,11,0.12);
  }
  .severo-grade-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .severo-grade-title {
    font-size: 0.85rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .severo-grade-val {
    font-size: 1.35rem;
    font-weight: 900;
    color: #f87171;
    font-family: 'Consolas', monospace;
  }
  .severo-grade-val.passed {
    color: #4ade80;
  }
  .severo-gold-btn-wrap {
    text-align: right;
  }
  .severo-btn-gold {
    background: linear-gradient(135deg, #fbbf24, #d97706);
    color: #0a0d14;
    border: 2px solid #fef08a;
    padding: 13px 22px;
    border-radius: 10px;
    font-weight: 900;
    font-size: 0.95rem;
    cursor: pointer;
    box-shadow: 0 4px 18px rgba(245,158,11,0.35);
    transition: transform 0.15s, filter 0.15s;
  }
  .severo-btn-gold:hover {
    transform: translateY(-2px);
    filter: brightness(1.08);
  }
  .severo-id-tag {
    margin-top: 6px;
    font-size: 0.8rem;
    font-family: 'Consolas', monospace;
    color: var(--gold-light);
  }
  .severo-id-tag code {
    background: rgba(0,0,0,0.45);
    padding: 2px 7px;
    border-radius: 4px;
    color: #4ade80;
    border: 1px solid #334155;
  }

  /* Alerta cuando el alumno pulsa el botón dorado con su ratón */
  .severo-alert {
    padding: 13px 16px;
    border-radius: 10px;
    margin-bottom: 18px;
    font-size: 0.9rem;
    line-height: 1.45;
    display: none;
  }
  .severo-alert.error {
    background: rgba(239,68,68,0.16);
    border: 1px solid #ef4444;
    color: #fecaca;
  }
  .severo-alert.success {
    background: rgba(34,197,94,0.18);
    border: 1px solid #22c55e;
    color: #bbf7d0;
  }

  /* Banner de Flag conseguida */
  .severo-flag-banner {
    background: linear-gradient(135deg, rgba(34,197,94,0.24), rgba(245,158,11,0.16));
    border: 2px solid var(--green);
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 22px;
    text-align: center;
    box-shadow: 0 0 35px rgba(34,197,94,0.3);
    display: none;
  }
  .severo-flag-banner h2 {
    color: #4ade80;
    font-size: 1.35rem;
    margin-bottom: 6px;
  }
  .severo-flag-code {
    display: inline-block;
    margin-top: 10px;
    background: #052e16;
    border: 1px solid #22c55e;
    color: #86efac;
    font-family: 'Consolas', monospace;
    font-size: 1.15rem;
    padding: 9px 20px;
    border-radius: 8px;
    user-select: all;
  }

  /* Grid principal */
  .severo-grid {
    display: grid;
    grid-template-columns: 1.15fr 0.85fr;
    gap: 20px;
    align-items: start;
  }
  @media (max-width: 992px) {
    .severo-grid { grid-template-columns: 1fr; }
  }
  .severo-panel {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
    margin-bottom: 20px;
  }
  .severo-panel-title {
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--cyan);
    margin-bottom: 12px;
    font-weight: 800;
  }

  /* Formulario de lloros */
  .severo-textarea {
    width: 100%;
    min-height: 92px;
    background: var(--bg-console);
    border: 2px solid #334155;
    color: #fff;
    padding: 12px 14px;
    border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.94rem;
    resize: vertical;
    margin-bottom: 12px;
  }
  .severo-textarea:focus {
    outline: none;
    border-color: var(--cyan);
  }
  .severo-btn-row {
    display: flex;
    gap: 10px;
    margin-bottom: 18px;
  }
  .severo-btn-send {
    flex: 1;
    background: linear-gradient(135deg, #38bdf8, #0284c7);
    color: #07090e;
    border: none;
    padding: 12px 18px;
    border-radius: 8px;
    font-weight: 800;
    font-size: 0.94rem;
    cursor: pointer;
  }
  .severo-btn-send:hover {
    filter: brightness(1.1);
  }
  .severo-btn-clear {
    background: transparent;
    border: 1px solid #475569;
    color: var(--muted);
    padding: 0 16px;
    border-radius: 8px;
    font-size: 0.85rem;
    cursor: pointer;
  }
  .severo-btn-clear:hover {
    color: #fff;
    border-color: #94a3b8;
  }

  /* Escudo Anti-Listillos + Monitor en Vivo */
  .severo-waf-box {
    background: var(--bg-console);
    border: 1px solid #1e293b;
    border-left: 4px solid var(--gold);
    border-radius: 8px;
    padding: 15px 16px;
  }
  .severo-waf-header {
    font-size: 0.84rem;
    color: var(--gold-light);
    font-weight: 700;
    margin-bottom: 6px;
  }
  .severo-waf-desc {
    font-size: 0.83rem;
    color: var(--muted);
    line-height: 1.45;
    margin-bottom: 12px;
  }
  .severo-waf-desc code {
    color: #f87171;
    background: rgba(239,68,68,0.12);
    padding: 1px 5px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
  }
  .severo-preview-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--cyan);
    margin-bottom: 6px;
    display: flex;
    justify-content: space-between;
  }
  .severo-preview-output {
    background: #0d1322;
    border: 1px solid #26334d;
    border-radius: 6px;
    padding: 11px 13px;
    font-family: 'Consolas', monospace;
    font-size: 0.92rem;
    min-height: 44px;
    word-break: break-all;
    color: #cbd5e1;
  }
  .xss-tag-survived {
    background: rgba(34,197,94,0.22);
    color: #4ade80;
    border: 1px solid #22c55e;
    padding: 1px 5px;
    border-radius: 4px;
    font-weight: 800;
  }
  .severo-waf-feedback {
    margin-top: 9px;
    font-size: 0.83rem;
    line-height: 1.45;
    color: #cbd5e1;
  }

  /* Ventana de Simulación de Don Severo */
  .severo-sim-screen {
    background: #07090e;
    border: 2px solid #334155;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 16px;
  }
  .severo-sim-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 9px;
    margin-bottom: 12px;
    font-size: 0.78rem;
    color: var(--muted);
    font-family: 'Consolas', monospace;
  }
  .severo-avatar-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }
  .severo-avatar {
    font-size: 2.1rem;
    background: #1e293b;
    width: 52px;
    height: 52px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 2px solid var(--gold);
  }
  .severo-speech {
    background: #111827;
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 0.88rem;
    line-height: 1.5;
    color: #e5e7eb;
  }

  /* Widget Chuleta: Macro de Accesibilidad de Don Severo */
  .severo-macro-card {
    background: rgba(56,189,248,0.07);
    border: 1px dashed rgba(56,189,248,0.45);
    border-radius: 10px;
    padding: 16px;
    font-size: 0.85rem;
    line-height: 1.5;
  }
  .severo-macro-card h4 {
    color: var(--cyan);
    font-size: 0.9rem;
    margin-bottom: 6px;
  }
  .severo-btn-deny {
    background: #1e293b;
    border: 1px solid #ef4444;
    color: #fca5a5;
    padding: 7px 12px;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 700;
    cursor: pointer;
    margin: 8px 0;
  }
  .severo-btn-deny:hover {
    background: rgba(239,68,68,0.2);
  }
  .severo-code-snippet {
    display: block;
    background: #05070b;
    border: 1px solid #1e293b;
    padding: 9px 11px;
    border-radius: 6px;
    font-family: 'Consolas', monospace;
    color: #4ade80;
    font-size: 0.84rem;
    margin: 6px 0;
    user-select: all;
  }
</style>

<div class="severo-wrap">
  <!-- Cabecera 50º Aniversario -->
  <div class="severo-header">
    <div class="severo-badge">🎓 1976 – 2026 · 50º Aniversario de los Estudios de Informática · Jornadas InnoSoft ETSII</div>
    <h1>👨‍🏫 Portal de Revisiones v1.976: <span>El 4.99 de Don Severo</span></h1>
    <p class="severo-story">
      <strong>Don Severo</strong> lleva dando clase desde que se fundaron los estudios de Informática en <strong>1976</strong>
      (él compilaba código mirando al trasluz agujeros en tarjetas perforadas). Te ha puesto un <strong>4.99</strong> y dice
      que no piensa dar libre para ir a las charlas de <strong>InnoSoft</strong>.
    </p>
    <div id="ctf-server-timer-box" style="margin-top:14px; padding:10px 16px; border-radius:10px; background:rgba(15,23,42,0.92); border:1px solid #334155; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
      <span id="ctf-server-timer-label" style="font-weight:700; color:#e2e8f0; font-size:0.92rem;">⏱️ Sincronizando cronómetro del reto con el servidor...</span>
      <span id="ctf-server-timer-clock" style="font-family:Consolas,monospace; font-size:1.15rem; font-weight:800; padding:4px 12px; border-radius:6px; background:#1e293b; color:#38bdf8;">--:--</span>
    </div>
  </div>

  <!-- Panel del Botón Dorado -->
  <div class="severo-gold-panel">
    <div class="severo-grade-box">
      <span class="severo-grade-title">📋 Acta Oficial de Fundamentos Ancestrales (Curso 50º Aniversario)</span>
      <span id="severo-grade-display" class="severo-grade-val">NOTA ACTUAL: 4.99 (SUSPENSO — SIN PERMISO PARA INNOSOFT)</span>
    </div>
    <div class="severo-gold-btn-wrap">
      <button type="button" id="comprar-soborno-al-profesor-btn" class="severo-btn-gold">
        🏆 APROBAR A TODOS CON 10 Y DAR DÍA LIBRE PARA INNOSOFT
      </button>
    </div>
  </div>

  <div id="severo-top-alert" class="severo-alert"></div>

  <!-- Banner de Flag (oculto hasta que Don Severo pulse el botón) -->
  <div id="severo-flag-banner" class="severo-flag-banner">
    <h2>🎉 ¡ACTA FIRMADA POR EL NAVEGADOR DE DON SEVERO! 🎉</h2>
    <p>Tu XSS ha obligado a la sesión de Don Severo a pulsar el Botón Dorado de Aprobado General. ¡Tienes un 10 y vía libre para InnoSoft!</p>
    <div id="severo-flag-code" class="severo-flag-code"></div>
  </div>

  <div class="severo-grid">
    <!-- Columna Izquierda: Formulario de Lloros + Cortafuegos con Monitor en Vivo -->
    <div class="severo-panel">
      <div class="severo-panel-title">📨 Buzón de Lloros y Reclamaciones al Profesor</div>

      <form id="severo-claim-form">
        <textarea
          id="severo-claim-input"
          class="severo-textarea"
          placeholder="Escribe aquí tu reclamación para Don Severo (o inyecta tu etiqueta HTML/JS)..."
        ></textarea>
        <div class="severo-btn-row">
          <button type="submit" class="severo-btn-send">📨 Enviar Lloro a Don Severo</button>
          <button type="button" id="severo-btn-clear" class="severo-btn-clear">Limpiar</button>
        </div>
      </form>

      <!-- Escudo Anti-Listillos con Monitor en Vivo -->
      <div class="severo-waf-box">
        <div class="severo-waf-header">🛡️ Cortafuegos Artesanal de Don Severo (Programado en 1998)</div>

        <div class="severo-preview-label">
          <span>🔎 MONITOR EN VIVO</span>
          <span style="color:#22c55e; font-weight:bold;">● TIEMPO REAL</span>
        </div>
        <div id="severo-preview-output" class="severo-preview-output"></div>
        <div id="severo-waf-feedback" class="severo-waf-feedback"></div>
      </div>
    </div>

    <!-- Columna Derecha: Simulación de la Pantalla de Don Severo + Chuleta de Macro -->
    <div class="severo-panel">
      <div class="severo-panel-title">👀 Simulación en Vivo: Ordenador de Don Severo</div>

      <div class="severo-sim-screen">
        <div class="severo-sim-topbar">
          <span>🖥️ Sesión activa: <strong>usuario = Don_Severo (Catedrático 1976)</strong></span>
          <span style="color:#4ade80;">● Permisos de Acta: TOTALES</span>
        </div>

        <div class="severo-avatar-row">
          <div class="severo-avatar">👨‍🏫</div>
          <div>
            <div style="font-weight:800; color:#fff;">Catedrático Don Severo</div>
            <div style="font-size:0.78rem; color:#94a3b8;">Leyendo reclamaciones mientras toma café de máquina...</div>
          </div>
        </div>

        <div id="severo-speech" class="severo-speech">
          💬 <em>«Esperando reclamaciones... Más vale que no vengáis a pedirme esa décima del 4.99 para ir a ver charlas de InnoSoft.»</em>
        </div>
      </div>

      <!-- La Chuleta Disimulada: Macro de Accesibilidad -->
      <div class="severo-macro-card">
        <h4>⚙️ Macro de Accesibilidad de Don Severo (Modo Desarrollador)</h4>
        <p style="margin-bottom:6px; color:#cbd5e1;">
          <em>Nota mental de Don Severo: Para no desgastar la bola de mi ratón IBM de 1982, he creado este botón de atajo que ejecuta JavaScript automáticamente:</em>
        </p>
        <button type="button" id="boton-denegar" class="severo-btn-deny">
          👎 Botón de prueba: Denegar Revisión (id="boton-denegar")
        </button>
        <div style="font-size:0.8rem; color:#94a3b8; margin-top:4px;">
          Comando JavaScript que utiliza el navegador para hacer clic en un botón por su ID:
        </div>
        <code class="severo-code-snippet">document.getElementById('boton-denegar').click()</code>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const _k = __XOR_KEY__;
  const _encFlag = __ENC_FLAG_JSON__;
  function decodeFlag() {
    return _encFlag.map(b => String.fromCharCode(b ^ _k)).join("");
  }

  let isDonSeveroSession = false;
  let denyTriggered = false;

  const btnGold = document.getElementById("comprar-soborno-al-profesor-btn");
  const btnDeny = document.getElementById("boton-denegar");
  const gradeDisplay = document.getElementById("severo-grade-display");
  const topAlert = document.getElementById("severo-top-alert");
  const flagBanner = document.getElementById("severo-flag-banner");
  const flagCode = document.getElementById("severo-flag-code");
  const claimForm = document.getElementById("severo-claim-form");
  const claimInput = document.getElementById("severo-claim-input");
  const btnClear = document.getElementById("severo-btn-clear");
  const previewOutput = document.getElementById("severo-preview-output");
  const wafFeedback = document.getElementById("severo-waf-feedback");
  const severoSpeech = document.getElementById("severo-speech");

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  const OPEN_SCRIPT_RE = new RegExp("<" + "script>", "i");
  const CLOSE_SCRIPT_RE = new RegExp("<" + "/script>", "i");
  const FULL_SCRIPT_BLOCK_RE = new RegExp("<" + "script>([\\s\\S]*?)<" + "/script>", "i");

  // El filtro defectuoso de Don Severo: reemplaza la etiqueta de apertura y cierre UNA SOLA VEZ
  function applyDonSeveroFilter(rawText) {
    return rawText
      .replace(OPEN_SCRIPT_RE, "")
      .replace(CLOSE_SCRIPT_RE, "");
  }

  function updateLiveMonitor() {
    const raw = claimInput.value;
    if (!raw) {
      previewOutput.innerHTML = `<span style="color:#64748b;">(Escribe algo arriba para ver cómo lo filtra Don Severo...)</span>`;
      wafFeedback.innerHTML = "";
      return;
    }

    const filtered = applyDonSeveroFilter(raw);
    const hasOpenScript = OPEN_SCRIPT_RE.test(filtered);
    const hasCloseScript = CLOSE_SCRIPT_RE.test(filtered);

    // Resaltar visualmente si las etiquetas de apertura y cierre han sobrevivido al filtro
    let escapedFiltered = escapeHtml(filtered);
    escapedFiltered = escapedFiltered
      .replace(/&lt;script&gt;/gi, `<span class="xss-tag-survived">&lt;script&gt;</span>`)
      .replace(/&lt;\/script&gt;/gi, `<span class="xss-tag-survived">&lt;/script&gt;</span>`);

    previewOutput.innerHTML = escapedFiltered || `<span style="color:#ef4444;">(El filtro ha borrado toda tu etiqueta y no ha quedado nada)</span>`;

    if (hasOpenScript && hasCloseScript) {
      wafFeedback.innerHTML = "";
    } else if (/script/i.test(raw)) {
      wafFeedback.innerHTML =
        `🛡️ <strong>Cortafuegos:</strong> El cortafuegos ha bloqueado tu mensaje por contener texto no permitido ('script').`;
    } else {
      wafFeedback.innerHTML = "";
    }
  }

  // Click en el Botón Dorado (#comprar-soborno-al-profesor-btn)
  btnGold.addEventListener("click", () => {
    if (!isDonSeveroSession) {
      topAlert.className = "severo-alert error";
      topAlert.innerHTML =
        `❌ <strong>¡Quieto ahí, milenial!</strong> Tus dedos de alumno no tienen permisos de Catedrático de 1976. ` +
        `El botón dorado solo responde si lo pulsa el propio navegador de <code>Don_Severo</code> al abrir tu reclamación.`;
      topAlert.style.display = "block";
      return;
    }

    // ¡Ejecutado desde la sesión simulada de Don Severo!
    const flag = decodeFlag();
    gradeDisplay.textContent = "NOTA ACTUAL: 10.0 (MATRÍCULA DE HONOR — DÍA LIBRE PARA INNOSOFT)";
    gradeDisplay.classList.add("passed");
    flagCode.textContent = flag;
    flagBanner.style.display = "block";

    topAlert.className = "severo-alert success";
    topAlert.innerHTML =
      `🏆 <strong>¡ EJECUCIÓN XSS EXITOSA !</strong> El navegador de <code>Don_Severo</code> ha ejecutado tu script y ha firmado el acta.`;
    topAlert.style.display = "block";

    severoSpeech.innerHTML =
      `😱 <strong>Don Severo:</strong> <em>«¡¿PERO QUÉ DEMONIOS HACE MI RATÓN DE BOLA?! ¡Se ha movido solo al Botón Dorado y ha firmado el Acta de Matrícula de Honor del 50º Aniversario! ¡Malditos hackers de InnoSoft!»</em>`;

    flagBanner.scrollIntoView({ behavior: "smooth", block: "center" });
  });

  // Click en el botón de prueba de la chuleta (#boton-denegar)
  btnDeny.addEventListener("click", () => {
    denyTriggered = true;
    severoSpeech.innerHTML =
      `👎 <strong>Macro de Don Severo ejecutada (<code>#boton-denegar</code>):</strong> <em>«Reclamación denegada automáticamente. ¡En 1976 programábamos en binario sin quejarnos!»</em>`;
  });

  // Envío del formulario de reclamación a Don Severo
  claimForm.addEventListener("submit", (e) => {
    e.preventDefault();
    topAlert.style.display = "none";

    const raw = claimInput.value;
    const filtered = applyDonSeveroFilter(raw);

    // Buscar si ha sobrevivido un bloque de script ejecutable tras el filtro
    const match = filtered.match(FULL_SCRIPT_BLOCK_RE);

    if (!match) {
      const frasesSevero = [
        "«¿Un 4.99? En 1976 eso se redondeaba a un 2.0 y encima tenías que limpiar las tarjetas perforadas. Nos vemos en septiembre.»",
        "«He leído tu lloro. Mi cortafuegos de 1998 ha limpiado cualquier etiqueta peligrosa. Siguiente reclamación.»",
        "«¿Que quieres ir a las Jornadas InnoSoft? ¡Cuando apruebes mi asignatura en el 100º Aniversario!»"
      ];
      const randomFrase = frasesSevero[Math.floor(Math.random() * frasesSevero.length)];
      severoSpeech.innerHTML =
        `☕ <strong>Don Severo abre tu mensaje filtrado:</strong><br>` +
        `<div style="margin:6px 0; padding:6px 10px; background:#07090e; border-left:3px solid #ef4444; font-family:monospace;">${escapeHtml(filtered || "(Mensaje vacío)")}</div>` +
        `💬 <em>${randomFrase}</em>`;
      return;
    }

    const jsCode = match[1].trim();
    isDonSeveroSession = true;
    denyTriggered = false;
    try {
      // Ejecutamos el código inyectado en el contexto de la sesión de Don Severo
      const fn = new Function(jsCode);
      fn();

      if (flagBanner.style.display === "block") {
        return;
      }

      if (denyTriggered) {
        // Se ejecutó la macro de denegar (#boton-denegar)
        return;
      }

      // Si ejecutó JS válido pero no pulsó ningún botón objetivo
      severoSpeech.innerHTML =
        `💬 <strong>Don Severo:</strong> <em>«He recibido tu reclamación... pero aquí no ha cambiado nada. ¡Sigues con tu 4.99!»</em>`;
    } catch (err) {
      severoSpeech.innerHTML =
        `⚠️ <strong>Don Severo:</strong> <em>«¿Qué clase de galimatías has enviado? Ni siquiera se ejecuta. ¡Siguiente!»</em>`;
    } finally {
      isDonSeveroSession = false;
    }
  });

  btnClear.addEventListener("click", () => {
    claimInput.value = "";
    topAlert.style.display = "none";
    updateLiveMonitor();
  });

  claimInput.addEventListener("input", updateLiveMonitor);
  updateLiveMonitor();

  // Sincronización del cronómetro individual de 20 min con el servidor CTFd
  (function initServerTimerSync() {
    const CHALLENGE_TITLE = "El 4.99 de Don Severo";
    const box = document.getElementById("ctf-server-timer-box");
    const lbl = document.getElementById("ctf-server-timer-label");
    const clk = document.getElementById("ctf-server-timer-clock");
    if (!box || !lbl || !clk) return;
    let endAtMs = null;
    let isTimerActive = false;

    function fmt(sec) {
      const s = Math.max(0, Math.floor(sec));
      return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
    }

    function renderTick() {
      if (!isTimerActive || endAtMs === null) {
        box.style.borderColor = "#475569";
        lbl.innerHTML = "⏸️ <strong>Cronómetro de este reto (20:00):</strong> Pendiente de inicio en el servidor";
        clk.textContent = "20:00";
        clk.style.background = "#1e293b";
        clk.style.color = "#94a3b8";
        return;
      }
      const rem = Math.max(0, Math.round((endAtMs - Date.now()) / 1000));
      clk.textContent = fmt(rem);
      if (rem <= 0) {
        box.style.borderColor = "#ef4444";
        lbl.innerHTML = "🔒 <strong style='color:#f87171;'>TIEMPO AGOTADO (00:00):</strong> Este reto ya ha cerrado el envío de flags en CTFd.";
        clk.style.background = "#7f1d1d";
        clk.style.color = "#fecaca";
      } else if (rem <= 300) {
        box.style.borderColor = "#f59e0b";
        lbl.innerHTML = "⚠️ <strong style='color:#fbbf24;'>¡Últimos minutos! Tiempo restante en servidor para enviar la flag:</strong>";
        clk.style.background = "#78350f";
        clk.style.color = "#fde68a";
      } else {
        box.style.borderColor = "#22c55e";
        lbl.innerHTML = "⏱️ <strong>Tiempo restante en servidor para resolver y enviar la flag:</strong>";
        clk.style.background = "#052e16";
        clk.style.color = "#4ade80";
      }
    }

    async function syncServer() {
      try {
        const res = await fetch("/api/v1/challenges/timers", { credentials: "same-origin", cache: "no-store" });
        if (res.ok) {
          const json = await res.json();
          if (json && Array.isArray(json.data)) {
            const item = json.data.find(c => c.name === CHALLENGE_TITLE);
            if (item) {
              isTimerActive = Boolean(item.timer_active) && item.remaining_seconds !== null && item.remaining_seconds !== undefined;
              endAtMs = isTimerActive ? (Date.now() + Math.max(0, Number(item.remaining_seconds)) * 1000) : null;
              renderTick();
              return;
            }
          }
        }
      } catch (_e) {}
      try {
        const lRes = await fetch("/api/v1/challenges", { credentials: "same-origin", cache: "no-store" });
        if (!lRes.ok) return;
        const lJson = await lRes.json();
        if (!lJson || !Array.isArray(lJson.data)) return;
        const found = lJson.data.find(c => c.name === CHALLENGE_TITLE);
        if (!found) return;
        const dRes = await fetch("/api/v1/challenges/" + found.id, { credentials: "same-origin", cache: "no-store" });
        if (!dRes.ok) return;
        const dJson = await dRes.json();
        if (dJson && dJson.data) {
          const sched = dJson.data.scheduled_at;
          if (sched && typeof sched === "string") {
            let norm = sched.trim();
            if (!norm.endsWith("Z") && !/[+-]\d{2}:\d{2}$/.test(norm)) norm += "Z";
            const startMs = Date.parse(norm);
            if (!Number.isNaN(startMs) && startMs > 1000000000000) {
              isTimerActive = true;
              endAtMs = startMs + 1200000;
              renderTick();
              return;
            }
          }
          isTimerActive = false;
          endAtMs = null;
          renderTick();
        }
      } catch (_e2) {}
    }

    syncServer();
    setInterval(renderTick, 1000);
    setInterval(syncServer, 8000);
  })();
})();
</script>
""".replace("__XOR_KEY__", str(_XOR_KEY)).replace("__ENC_FLAG_JSON__", _ENC_FLAG_JSON)


# ==============================================================================
# MODO SERVIDOR AUTÓNOMO (http.server por si se ejecuta con --serve)
# ==============================================================================

def render_standalone_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>El 4.99 de Don Severo | 50º Aniversario ETSII - InnoSoft</title>
  <style>
    body {{
      background: radial-gradient(circle at top, #1e1b4b 0%, #0a0d14 55%);
      margin: 0;
      padding: 20px;
      min-height: 100vh;
    }}
    .standalone-container {{
      max-width: 1120px;
      margin: 0 auto;
    }}
  </style>
</head>
<body>
  <div class="standalone-container">
    {EMBEDDED_CHALLENGE_PAGE_HTML}
  </div>
</body>
</html>"""


class XSSChallengeHTTPHandler(BaseHTTPRequestHandler):
    """Manejador HTTP autónomo para el modo `--serve`."""

    def do_GET(self):
        body = render_standalone_html().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_str, *args):
        sys.stderr.write(f"[Don-Severo-XSS] {self.address_string()} - {format_str % args}\n")


def upsert_ctfd_challenge_page() -> None:
    """
    Registra o actualiza la página interactiva del reto directamente en el modelo `Pages`
    de CTFd en las rutas `don-severo` y `don-severo/`, para que funcione directamente
    en `http://localhost:8000/don-severo` y dentro del túnel de Cloudflare de vuestro dominio.
    """
    from CTFd.cache import cache
    from CTFd.models import Pages, db

    for route_variant in (CHALLENGE_ROUTE, f"{CHALLENGE_ROUTE}/"):
        page = Pages.query.filter_by(route=route_variant).first()
        if page is None:
            page = Pages(
                title=CHALLENGE_NAME,
                route=route_variant,
                content=EMBEDDED_CHALLENGE_PAGE_HTML,
                draft=False,
                hidden=True,
                auth_required=False,
                format="html",
            )
            db.session.add(page)
            print(f"    → Página interactiva de CTFd registrada en: /{route_variant}")
        else:
            page.title = CHALLENGE_NAME
            page.content = EMBEDDED_CHALLENGE_PAGE_HTML
            page.draft = False
            page.hidden = True
            page.auth_required = False
            page.format = "html"
            print(f"    → Página interactiva de CTFd actualizada en: /{route_variant}")

    db.session.commit()
    cache.clear()


# ==============================================================================
# No es necesario editar nada por debajo de esta línea (Seed de CTFd)
# ==============================================================================


def challenge_exists(name: str) -> bool:
    from CTFd.models import Challenges
    return Challenges.query.filter_by(name=name).first() is not None


def seed():
    cfg = load_config()

    if not cfg.get("enabled", True):
        print(f"[skip] '{CHALLENGE_NAME}' desactivado en config.yml")
        return

    try:
        from CTFd import create_app
        from CTFd.models import Challenges, Flags, Hints, Solutions, Tags, db
    except ModuleNotFoundError:
        print("[i] Entorno CTFd no detectado en local. Iniciando servidor web del reto...")
        run_server()
        return

    challenge_state = cfg.get("state", "visible")
    app = create_app()

    with app.app_context():
        # Siempre registramos/actualizamos la página interactiva `/don-severo` en CTFd
        upsert_ctfd_challenge_page()

        existing = Challenges.query.filter_by(name=CHALLENGE_NAME).first()
        if existing is not None:
            existing.description = CHALLENGE_DESCRIPTION
            Hints.query.filter_by(challenge_id=existing.id).delete()
            prev_hint_id = None
            for i, h in enumerate(HINTS, 1):
                reqs = {"prerequisites": [prev_hint_id]} if prev_hint_id else None
                hint_obj = Hints(
                    challenge_id=existing.id,
                    title=h["title"],
                    content=h["content"],
                    cost=h["cost"],
                    type="standard",
                    requirements=reqs,
                )
                db.session.add(hint_obj)
                db.session.commit()
                prev_hint_id = hint_obj.id
            db.session.commit()
            print(f"[ok] '{CHALLENGE_NAME}' ya existía en la BD — descripción, pistas encadenadas y ruta /{CHALLENGE_ROUTE} actualizadas.")
            return

        print(f"[+] Creando reto: {CHALLENGE_NAME!r} ({challenge_state})")

        # 1. Reto
        challenge = Challenges(
            name=CHALLENGE_NAME,
            description=CHALLENGE_DESCRIPTION,
            attribution=CHALLENGE_ATTRIBUTION,
            value=CHALLENGE_VALUE,
            category=CHALLENGE_CATEGORY,
            type="standard",
            state=challenge_state,
            max_attempts=0,
        )
        db.session.add(challenge)
        db.session.commit()

        # 2. Flag
        flag = Flags(
            challenge_id=challenge.id,
            content=FLAG_CONTENT,
            type=FLAG_TYPE,
            data=FLAG_DATA,
        )
        db.session.add(flag)
        db.session.commit()

        # 3. Pistas encadenadas secuencialmente
        prev_hint_id = None
        for i, h in enumerate(HINTS, 1):
            reqs = {"prerequisites": [prev_hint_id]} if prev_hint_id else None
            hint_obj = Hints(
                challenge_id=challenge.id,
                title=h["title"],
                content=h["content"],
                cost=h["cost"],
                type="standard",
                requirements=reqs,
            )
            db.session.add(hint_obj)
            db.session.commit()
            prev_hint_id = hint_obj.id
            print(f"    → Pista {i} (coste {h['cost']} pts, req={reqs})")

        # 4. Tags
        for tag_value in TAGS:
            db.session.add(Tags(challenge_id=challenge.id, value=tag_value))
        db.session.commit()

        # 5. Solución/writeup
        db.session.add(Solutions(
            challenge_id=challenge.id,
            content=SOLUTION,
            state="hidden",
        ))
        db.session.commit()

        print(f"[ok] '{CHALLENGE_NAME}' creado. Flag: {FLAG_CONTENT}")


def run_server():
    """Levanta en primer plano el servidor web autónomo del reto en http://localhost:5004."""
    server = ThreadingHTTPServer(("0.0.0.0", CHALLENGE_PORT), XSSChallengeHTTPHandler)
    print(f"[*] Reto '{CHALLENGE_NAME}' disponible en http://localhost:{CHALLENGE_PORT}")
    print("[*] Pulsa Ctrl+C para detener el servidor.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido.")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"Seed y servidor web para: {CHALLENGE_NAME}")
    parser.add_argument(
        "--serve",
        action="store_true",
        help=f"Inicia únicamente el servidor web autónomo del reto en el puerto {CHALLENGE_PORT}",
    )
    args = parser.parse_args()

    if args.serve:
        run_server()
    else:
        seed()

