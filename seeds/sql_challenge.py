#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
seeds/sql_challenge.py
----------------------
Reto Web SQL Injection (UNION SQLi "Con Ruedines"):
  🕹️ "La Cápsula del Tiempo de 1976"
  Jornadas InnoSoft — 50º Aniversario de los Estudios de Informática (ETSII)

Este archivo es 100% autónomo (todo en uno, sin ningún archivo extra):
  1. Inserta el reto, la flag, las pistas, las etiquetas y la solución en CTFd.
  2. Registra automáticamente la aplicación interactiva del reto como una Página
     interna de CTFd en la ruta `/capsula-1976` (y `/capsula-1976/`), de modo que
     funciona directamente dentro de `http://localhost:8000/capsula-1976/` y a través
     de cualquier túnel de Cloudflare que apunte a CTFd, ¡sin tocar Nginx ni abrir puertos extra!
  3. Además incluye servidor HTTP + SQLite autónomo (`--serve`) por si se quiere
     ejecutar de forma aislada fuera de CTFd.
"""

import argparse
import html
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SEEDS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SEEDS_DIR, ".."))

# ── ← EDITAR ──────────────────────────────────────────────────────────────────
# Clave única en snake_case — debe coincidir con la entrada en config.yml / config.json
CONFIG_KEY = "sql_challenge"
# ──────────────────────────────────────────────────────────────────────────────

CHALLENGE_PORT = int(os.environ.get("SQL_CHALLENGE_PORT", "5002"))
CHALLENGE_ROUTE = "capsula-1976"
DB_PATH = os.path.join(tempfile.gettempdir(), "innosoft_capsula_1976.db")


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

CHALLENGE_NAME        = "La Cápsula del Tiempo de 1976"
CHALLENGE_CATEGORY    = "Web"
CHALLENGE_VALUE       = 150
CHALLENGE_ATTRIBUTION = "InnoSoft Days — 50º Aniversario ETSII"

CHALLENGE_DESCRIPTION = """\
## 🕹️ La Cápsula del Tiempo de 1976

¡Bienvenido al Catálogo Digital del **50º Aniversario de los Estudios de Informática (1976–2026)**!  
Con motivo de nuestras Bodas de Oro en las **Jornadas InnoSoft de la ETSII**, hemos digitalizado todas las reliquias históricas guardadas en los sótanos de la escuela desde 1976.

Cuenta la leyenda que los primeros profesores de 1976 enterraron una **Cápsula del Tiempo** con un secreto inconfesable (la **Flag**), pero el Archivero Jefe la ha movido a una tabla aparte para que ningún curioso la encuentre desde el buscador público antes de la clausura de InnoSoft.

Por suerte para ti, el becario de sistemas se ha dejado encendido el **Previsualizador de Consultas SQL en Vivo**, tres botones de prueba y un **post-it pegado en el monitor**...

### 🎯 Objetivo
Utiliza el buscador del museo para unir la tabla secreta de la cápsula del tiempo y extraer la flag del 50º Aniversario. *(¡No necesitas saber SQL de antemano, fíjate en los botones de ejemplo y en el monitor en vivo!)*

### 🌐 Acceso al reto
👉 **[🕹️ Abrir el Catálogo del Museo (La Cápsula de 1976)](/capsula-1976)**
"""

# La flag exacta que el participante debe enviar
FLAG_CONTENT = "INNOSOFT{50_4n1v3rs4r10_d3sd3_l4_t4rj3t4_p3rf0r4d4}"
FLAG_TYPE    = "static"   # "static" (exacta) | "regex" (expresión regular)
FLAG_DATA    = ""         # "" = case-sensitive | "case_insensitive"

# Pistas opcionales
HINTS = [
    {
        "title":   "Pista 1 — Los botones de ejemplo y el Post-it",
        "content": (
            "No necesitas saber SQL de memoria. Pulsa los **3 botones de búsqueda rápida** que hay encima "
            "del buscador y observa en la consola negra qué comandos se envían a la base de datos. "
            "Luego lee el **Post-it amarillo** de la derecha para saber cómo se llama la tabla secreta y sus 2 columnas."
        ),
        "cost":    0,    # gratis
    },
    {
        "title":   "Pista 2 — Cómo combinar las piezas (Comilla, UNION y Comentario)",
        "content": (
            "1. Escribe una comilla simple `'` para cerrar el texto de búsqueda.\n"
            "2. Igual que hace el **Botón 2**, usa `UNION SELECT col1, col2 FROM tabla` pero cambiando "
            "los nombres por los que aparecen en el Post-it amarillo (`codigo_secreto, contenido_flag` y `capsula_1976`).\n"
            "3. Igual que hace el **Botón 3**, termina escribiendo `--` para tachar y anular el `%' AND oculto = 0` del final."
        ),
        "cost":    25,   # cuesta 25 puntos
    },
    {
        "title":   "Pista 3 — El payload exacto",
        "content": (
            "Escribe exactamente esto en la barra del buscador y pulsa **Buscar en el Archivo**:\n"
            "```sql\n"
            "' UNION SELECT codigo_secreto, contenido_flag FROM capsula_1976 --\n"
            "```"
        ),
        "cost":    50,
    },
]

# Etiquetas para filtrar retos en el panel
TAGS = ["web", "sqli", "union", "innosoft", "50-aniversario"]

# Writeup/solución (estado "hidden" → solo el admin la ve hasta publicarla)
SOLUTION = """\
## Solución — La Cápsula del Tiempo de 1976 (UNION SQLi con Ruedines)

### 1. Análisis de la interfaz
Al entrar al catálogo del **Museo del 50º Aniversario**, vemos tres elementos clave diseñados para guiar la explotación:
1. **Consola de Vista Previa SQL en Tiempo Real:** Muestra cómo se concatena nuestra búsqueda directamente en la consulta:
   ```sql
   SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo WHERE nombre_reliquia LIKE '%<INPUT>%' AND oculto = 0
   ```
2. **Botones de Búsqueda Rápida:**
   - El **Botón 2 (`Incluir donaciones de antiguos alumnos`)** revela cómo combinar resultados de otra tabla de 2 columnas usando `UNION SELECT col1, col2 FROM tabla`.
   - El **Botón 3 (`Modo Prueba del Archivero`)** revela cómo cerrar la comilla con `'` y usar `--` para comentar/tachar el resto de la consulta (`%' AND oculto = 0`).
3. **El Post-it del Archivero:** Nos chiva que la cápsula está en la tabla **`capsula_1976`** y que sus dos columnas se llaman **`codigo_secreto`** y **`contenido_flag`**.

### 2. Construcción del Payload
Introducimos en el buscador:
```sql
' UNION SELECT codigo_secreto, contenido_flag FROM capsula_1976 --
```

La consulta resultante es:
```sql
SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo WHERE nombre_reliquia LIKE '%' UNION SELECT codigo_secreto, contenido_flag FROM capsula_1976 --%' AND oculto = 0
```

### 3. Flag obtenida
Al final de la tabla de resultados aparece el contenido de la cápsula de 1976:
```
INNOSOFT{50_4n1v3rs4r10_d3sd3_l4_t4rj3t4_p3rf0r4d4}
```
"""


# ==============================================================================
# PÁGINA INTERACTIVA INTEGRADA EN CTFd (/capsula-1976 y /capsula-1976/)
# ==============================================================================
# Al registrarse como un objeto `Pages` dentro de la propia BD de CTFd, funciona
# directamente en http://localhost:8000/capsula-1976/ y dentro del túnel de
# Cloudflare de la plataforma sin configurar proxies ni puertos adicionales.

_XOR_KEY = 76
_ENC_FLAG_JSON = json.dumps([ord(c) ^ _XOR_KEY for c in FLAG_CONTENT])

EMBEDDED_CHALLENGE_PAGE_HTML = r"""
<style>
  .museum-wrap {
    --bg-dark: #0b0f19;
    --bg-panel: #131b2e;
    --bg-console: #070a10;
    --gold: #f59e0b;
    --gold-light: #fcd34d;
    --cyan: #38bdf8;
    --green: #22c55e;
    --red: #ef4444;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --border: #26334d;
    color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    padding: 18px 0 48px;
  }
  .museum-header {
    background: linear-gradient(135deg, rgba(245,158,11,0.16), rgba(56,189,248,0.10));
    border: 1px solid rgba(245,158,11,0.45);
    border-radius: 14px;
    padding: 24px 28px;
    margin-bottom: 22px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.35);
    background-color: #0f172a;
  }
  .museum-badge-50 {
    display: inline-block;
    background: linear-gradient(90deg, #f59e0b, #eab308);
    color: #0b0f19;
    font-weight: 800;
    font-size: 0.78rem;
    padding: 4px 12px;
    border-radius: 999px;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    margin-bottom: 10px;
  }
  .museum-header h1 {
    font-size: 1.75rem;
    color: #fff;
    margin-bottom: 8px;
    font-weight: 800;
  }
  .museum-header h1 span {
    color: var(--gold-light);
  }
  .museum-story {
    color: #cbd5e1;
    font-size: 0.94rem;
    line-height: 1.55;
    margin: 0;
  }
  .museum-story strong {
    color: var(--gold-light);
  }
  .museum-grid {
    display: grid;
    grid-template-columns: 1fr 320px;
    gap: 20px;
    align-items: start;
  }
  @media (max-width: 992px) {
    .museum-grid { grid-template-columns: 1fr; }
  }
  .museum-panel {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
    margin-bottom: 20px;
  }
  .museum-panel-title {
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--cyan);
    margin-bottom: 14px;
    font-weight: 700;
  }
  .museum-quick-help {
    font-size: 0.86rem;
    color: var(--muted);
    margin-bottom: 10px;
  }
  .museum-quick-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 18px;
  }
  .museum-btn-preset {
    background: #1e293b;
    border: 1px solid #334155;
    color: #f8fafc;
    padding: 9px 14px;
    border-radius: 8px;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.18s;
    font-weight: 600;
  }
  .museum-btn-preset:hover {
    border-color: var(--gold);
    background: rgba(245,158,11,0.15);
    transform: translateY(-1px);
  }
  .museum-btn-preset.active {
    border-color: var(--gold);
    background: rgba(245,158,11,0.22);
    color: var(--gold-light);
  }
  .museum-search-row {
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
  }
  .museum-search-input {
    flex: 1;
    background: var(--bg-console);
    border: 2px solid #334155;
    color: #fff;
    padding: 12px 16px;
    border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.96rem;
  }
  .museum-search-input:focus {
    outline: none;
    border-color: var(--cyan);
  }
  .museum-btn-search {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: #0b0f19;
    border: none;
    padding: 0 22px;
    border-radius: 8px;
    font-weight: 800;
    font-size: 0.92rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .museum-btn-search:hover {
    filter: brightness(1.1);
  }
  .museum-btn-reset {
    background: transparent;
    border: 1px solid #475569;
    color: var(--muted);
    padding: 0 14px;
    border-radius: 8px;
    font-size: 0.84rem;
    cursor: pointer;
  }
  .museum-btn-reset:hover {
    color: #fff;
    border-color: #94a3b8;
  }
  .museum-console-box {
    background: var(--bg-console);
    border: 1px solid #1e293b;
    border-left: 4px solid var(--cyan);
    border-radius: 8px;
    padding: 14px 16px;
    font-family: 'Consolas', 'Courier New', monospace;
  }
  .museum-console-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.76rem;
    color: var(--muted);
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .museum-console-live-dot {
    color: var(--green);
    font-weight: bold;
  }
  .museum-sql-preview {
    font-size: 0.94rem;
    line-height: 1.55;
    word-break: break-all;
    color: #93c5fd;
  }
  .sql-kw { color: #c084fc; font-weight: bold; }
  .sql-str { color: #fde047; }
  .sql-quote-break {
    background: rgba(239,68,68,0.28);
    color: #fca5a5;
    padding: 1px 4px;
    border-radius: 4px;
    font-weight: bold;
  }
  .sql-injected {
    color: #4ade80;
    font-weight: bold;
    background: rgba(34,197,94,0.12);
    padding: 1px 4px;
    border-radius: 4px;
  }
  .sql-commented {
    color: #64748b !important;
    text-decoration: line-through;
    opacity: 0.75;
  }
  .sql-dangling {
    color: #f87171;
    text-decoration: wavy underline #ef4444;
  }
  .museum-live-feedback {
    margin-top: 10px;
    padding-top: 9px;
    border-top: 1px dashed #1e293b;
    font-size: 0.84rem;
    color: #cbd5e1;
    font-family: 'Segoe UI', system-ui, sans-serif;
  }
  .museum-tutorial-banner {
    margin-top: 14px;
    background: rgba(56,189,248,0.1);
    border: 1px solid rgba(56,189,248,0.35);
    border-radius: 8px;
    padding: 12px 15px;
    font-size: 0.87rem;
    line-height: 1.5;
    color: #e0f2fe;
    display: none;
  }
  .museum-tutorial-banner code {
    background: rgba(0,0,0,0.4);
    padding: 2px 6px;
    border-radius: 4px;
    color: var(--gold-light);
    font-family: 'Consolas', monospace;
  }
  .museum-postit {
    background: #fef08a;
    color: #1c1917;
    padding: 20px 18px;
    border-radius: 4px 4px 14px 4px;
    box-shadow: 6px 8px 20px rgba(0,0,0,0.45);
    transform: rotate(1.2deg);
    font-family: 'Comic Sans MS', 'Segoe Print', 'Bradley Hand', cursive, sans-serif;
    border-top: 14px solid #facc15;
    margin-bottom: 18px;
  }
  .museum-postit h3 {
    font-size: 0.95rem;
    color: #991b1b;
    margin-bottom: 10px;
    text-transform: uppercase;
    border-bottom: 1px dashed #ca8a04;
    padding-bottom: 5px;
    font-weight: 800;
  }
  .museum-postit p {
    font-size: 0.88rem;
    line-height: 1.5;
    margin-bottom: 10px;
    color: #1c1917;
  }
  .museum-postit code {
    background: rgba(180,83,9,0.16);
    color: #7c2d12;
    font-weight: 800;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: 'Consolas', monospace;
  }
  .museum-cheat-card {
    background: rgba(19,27,46,0.95);
    border: 1px dashed #334155;
    border-radius: 10px;
    padding: 16px;
    font-size: 0.83rem;
    color: var(--muted);
    line-height: 1.5;
  }
  .museum-cheat-card h4 {
    color: var(--gold-light);
    margin-bottom: 8px;
    font-size: 0.88rem;
  }
  .museum-cheat-card ul {
    padding-left: 16px;
    margin: 0;
  }
  .museum-cheat-card li {
    margin-bottom: 6px;
  }
  .museum-cheat-card code {
    color: #4ade80;
    font-family: 'Consolas', monospace;
  }
  .museum-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 6px;
  }
  .museum-table th {
    text-align: left;
    background: #0f172a;
    color: var(--gold-light);
    padding: 11px 14px;
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    border-bottom: 2px solid var(--border);
  }
  .museum-table td {
    padding: 12px 14px;
    border-bottom: 1px solid #1e293b;
    font-size: 0.92rem;
    color: #e2e8f0;
  }
  .museum-col-year {
    font-family: 'Consolas', monospace;
    color: var(--cyan) !important;
    font-weight: 600;
  }
  .museum-flag-row td {
    background: rgba(34,197,94,0.18) !important;
    border-top: 2px solid var(--green);
    border-bottom: 2px solid var(--green);
    color: #fff !important;
    font-weight: bold;
  }
  .museum-flag-celebration {
    background: linear-gradient(135deg, rgba(34,197,94,0.22), rgba(16,185,129,0.1));
    border: 2px solid var(--green);
    border-radius: 12px;
    padding: 18px 22px;
    margin-bottom: 18px;
    text-align: center;
    box-shadow: 0 0 30px rgba(34,197,94,0.25);
    display: none;
  }
  .museum-flag-celebration h2 {
    color: #4ade80;
    font-size: 1.3rem;
    margin-bottom: 6px;
  }
  .museum-flag-code {
    display: inline-block;
    margin-top: 8px;
    background: #052e16;
    border: 1px solid #22c55e;
    color: #86efac;
    font-family: 'Consolas', monospace;
    font-size: 1.15rem;
    padding: 8px 18px;
    border-radius: 8px;
    user-select: all;
  }
  .museum-error-box {
    background: rgba(239,68,68,0.1);
    border: 1px solid var(--red);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 18px;
    display: none;
  }
  .museum-error-box h3 {
    color: #f87171;
    font-size: 0.95rem;
    margin-bottom: 6px;
  }
  .museum-error-raw {
    font-family: 'Consolas', monospace;
    font-size: 0.83rem;
    color: #fca5a5;
    background: rgba(0,0,0,0.35);
    padding: 8px 10px;
    border-radius: 6px;
    margin-bottom: 10px;
  }
  .museum-error-helper {
    color: #fef08a;
    font-size: 0.88rem;
    line-height: 1.45;
  }
</style>

<div class="museum-wrap">
  <div class="museum-header">
    <div class="museum-badge-50">🎓 1976 – 2026 · 50º Aniversario de los Estudios de Informática · Jornadas InnoSoft ETSII</div>
    <h1>🕹️ Archivo Histórico: <span>La Cápsula del Tiempo de 1976</span></h1>
    <p class="museum-story">
      Con motivo de las <strong>Bodas de Oro de los Estudios de Informática</strong> en las Jornadas InnoSoft,
      hemos digitalizado el catálogo de reliquias históricas de los sótanos de la ETSII. Cuenta la leyenda que los
      primeros catedráticos de 1976 guardaron una <strong>Cápsula del Tiempo con la Flag</strong> en la base de datos,
      pero el Archivero Jefe la ha movido a otra tabla para que no salga en el buscador público.
    </p>
    <div id="ctf-server-timer-box" style="margin-top:14px; padding:10px 16px; border-radius:10px; background:rgba(15,23,42,0.92); border:1px solid #334155; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
      <span id="ctf-server-timer-label" style="font-weight:700; color:#e2e8f0; font-size:0.92rem;">⏱️ Sincronizando cronómetro del reto con el servidor...</span>
      <span id="ctf-server-timer-clock" style="font-family:Consolas,monospace; font-size:1.15rem; font-weight:800; padding:4px 12px; border-radius:6px; background:#1e293b; color:#38bdf8;">--:--</span>
    </div>
  </div>

  <div class="museum-grid">
    <div>
      <div class="museum-panel">
        <div class="museum-panel-title">🔎 Buscador de Reliquias del Museo (v1.976)</div>

        <div class="museum-quick-buttons">
          <button type="button" id="btn-preset-1" class="museum-btn-preset">
            📼 Botón 1: Ver reliquias de los 70
          </button>
          <button type="button" id="btn-preset-2" class="museum-btn-preset">
            🤝 Botón 2: Incluir donaciones de antiguos alumnos
          </button>
          <button type="button" id="btn-preset-3" class="museum-btn-preset">
            🔧 Botón 3: Modo Prueba del Archivero (--)
          </button>
        </div>

        <form id="museum-search-form">
          <div class="museum-search-row">
            <input
              type="text"
              id="museum-search-input"
              class="museum-search-input"
              placeholder="Busca una reliquia o inyecta tu comando SQL aquí..."
              autocomplete="off"
            >
            <button type="submit" class="museum-btn-search">Buscar en el Archivo</button>
            <button type="button" id="museum-btn-reset" class="museum-btn-reset">Limpiar</button>
          </div>
        </form>

        <div class="museum-console-box">
          <div class="museum-console-header">
            <span>🖥️ Previsualizador de Consulta SQL en Tiempo Real (Debug Console)</span>
            <span class="museum-console-live-dot">● EN VIVO</span>
          </div>
          <div id="museum-sql-preview" class="museum-sql-preview"></div>
          <div id="museum-live-feedback" class="museum-live-feedback"></div>
        </div>

        <div id="museum-tutorial-banner" class="museum-tutorial-banner"></div>
      </div>

      <div class="museum-panel">
        <div class="museum-panel-title">🏛️ Resultados del Catálogo (2 Columnas)</div>

        <div id="museum-flag-celebration" class="museum-flag-celebration">
          <h2>🎉 ¡CÁPSULA DEL TIEMPO DE 1976 ABIERTA! 🎉</h2>
          <p>Has unido con éxito la tabla secreta del 50º Aniversario. Aquí tienes tu Flag para CTFd:</p>
          <div id="museum-flag-code" class="museum-flag-code"></div>
        </div>

        <div id="museum-error-box" class="museum-error-box">
          <h3>⚠️ Error devuelto por la Base de Datos SQLite:</h3>
          <div id="museum-error-raw" class="museum-error-raw"></div>
          <div id="museum-error-helper" class="museum-error-helper"></div>
        </div>

        <table class="museum-table">
          <thead>
            <tr>
              <th style="width: 68%;">Columna 1: Reliquia / Código (`nombre_reliquia`)</th>
              <th style="width: 32%;">Columna 2: Año / Contenido (`año_hallazgo`)</th>
            </tr>
          </thead>
          <tbody id="museum-results-body"></tbody>
        </table>
      </div>
    </div>

    <div>
      <div class="museum-postit">
        <h3>📌 NOTA PARA EL BECARIO DE SISTEMAS (NO BORRAR)</h3>
        <p>
          Ya he sacado la <strong>Cápsula del Tiempo</strong> de la tabla <code>catalogo_museo</code>
          para que ningún curioso la vea en el buscador durante las Jornadas InnoSoft.
        </p>
        <p>
          La he guardado en una tabla aparte llamada:<br>
          👉 <code>capsula_1976</code>
        </p>
        <p>
          Acuérdate de que esa tabla solo tiene <strong>dos columnas</strong>:<br>
          1️⃣ <code>codigo_secreto</code><br>
          2️⃣ <code>contenido_flag</code>
        </p>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const DB_TABLES = {
    catalogo_museo: [
      { id: 1, nombre_reliquia: "Tarjeta Perforada con mancha de café del primer examen de FORTRAN", "año_hallazgo": "1976", epoca: "70s", oculto: 0 },
      { id: 2, nombre_reliquia: "Manual original del terminal TeleType ASR-33 (subrayado con lágrimas)", "año_hallazgo": "1978", epoca: "70s", oculto: 0 },
      { id: 3, nombre_reliquia: "Cinta magnética de carrete abierto con apuntes de Ensamblador", "año_hallazgo": "1979", epoca: "70s", oculto: 0 },
      { id: 4, nombre_reliquia: "Ratón de bola IBM cuyo rodillo lleva sin limpiarse desde Naranjito '82", "año_hallazgo": "1982", epoca: "80s", oculto: 0 },
      { id: 5, nombre_reliquia: "Disquete flexible de 5¼ pulgadas con el Doom pirata en 4 partes", "año_hallazgo": "1993", epoca: "90s", oculto: 0 },
      { id: 6, nombre_reliquia: "Cable VGA del Salón de Actos que solo da imagen si lo doblas 47 grados", "año_hallazgo": "2004", epoca: "00s", oculto: 0 },
      { id: 7, nombre_reliquia: "Taza conmemorativa de las primeras Jornadas InnoSoft", "año_hallazgo": "2012", epoca: "10s", oculto: 0 },
      { id: 8, nombre_reliquia: "Prototipo IBM 5100 Experimental [RELIQUIA OCULTA EN EL SÓTANO]", "año_hallazgo": "1977", epoca: "70s", oculto: 1 }
    ],
    donaciones_alumnos: [
      { id: 1, objeto_donado: "Calculadora HP-35 Polaca Inversa que sobrevivió a Cálculo", autor: "Promoción del 81" },
      { id: 2, objeto_donado: "Floppy de 3½ con prácticas de Turbo Pascal 7.0", autor: "Antiguo Alumno '96" },
      { id: 3, objeto_donado: "Pen Drive de 128 MB encontrado en los laboratorios", autor: "Becario Anónimo '05" }
    ]
  };

  // La tabla capsula_1976 reconstruye la flag dinámicamente solo cuando el motor SQL la consulta
  const _k = __XOR_KEY__;
  const _encFlag = __ENC_FLAG_JSON__;
  function getCapsulaTable() {
    const f = _encFlag.map(b => String.fromCharCode(b ^ _k)).join('');
    return [
      {
        codigo_secreto: "MANIFIESTO_FUNDACIONAL_1976",
        contenido_flag: "«A los informáticos del año 2026: esperamos que ya no tengáis que programar haciendo agujeros en cartulinas.»"
      },
      {
        codigo_secreto: "APERTURA_BODAS_DE_ORO_76",
        contenido_flag: f
      }
    ];
  }

  let activePreset = "";
  const inputEl = document.getElementById("museum-search-input");
  const previewEl = document.getElementById("museum-sql-preview");
  const feedbackEl = document.getElementById("museum-live-feedback");
  const tutorialEl = document.getElementById("museum-tutorial-banner");
  const resultsBody = document.getElementById("museum-results-body");
  const errorBox = document.getElementById("museum-error-box");
  const errorRaw = document.getElementById("museum-error-raw");
  const errorHelper = document.getElementById("museum-error-helper");
  const flagBanner = document.getElementById("museum-flag-celebration");
  const flagCode = document.getElementById("museum-flag-code");

  const btn1 = document.getElementById("btn-preset-1");
  const btn2 = document.getElementById("btn-preset-2");
  const btn3 = document.getElementById("btn-preset-3");
  const btnReset = document.getElementById("museum-btn-reset");
  const formEl = document.getElementById("museum-search-form");

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function explainSqlError(errorMsg, rawInput) {
    const errLower = errorMsg.toLowerCase();
    if (errLower.includes("selects to the left and right of union do not have the same number of result columns")) {
      return "📏 ¡Casi lo tienes! El error dice que las dos tablas del UNION no tienen el mismo número de columnas. Recuerda que la tabla del museo muestra 2 columnas, así que después de UNION SELECT debes escribir exactamente 2 columnas separadas por una coma (mira el Post-it amarillo: codigo_secreto, contenido_flag).";
    }
    if (errLower.includes("no such table")) {
      return "🗂️ La base de datos dice que esa tabla no existe. Revisa el Post-it amarillo del Archivero: la tabla secreta se llama exactamente capsula_1976.";
    }
    if (errLower.includes("no such column")) {
      return "🏷️ Has puesto un nombre de columna que no existe en esa tabla. Revisa el Post-it amarillo: las dos columnas de la tabla capsula_1976 se llaman codigo_secreto y contenido_flag.";
    }
    if (errLower.includes("unrecognized token") && rawInput.includes("#")) {
      return "💡 Has intentado comentar con '#', pero en esta base de datos los comentarios se hacen con dos guiones seguidos: -- (fíjate en el Botón 3 de ejemplo).";
    }
    if (errLower.includes("syntax error") || errLower.includes("unrecognized token")) {
      if (rawInput.includes("'") && !rawInput.includes("--")) {
        return "✂️ Has cerrado la comilla simple ('), ¡bien hecho! Pero el final original de la consulta (%' AND oculto = 0) se ha quedado suelto y rompe la frase. Añade dos guiones (--) al final de tu texto para tachar y comentar lo que sobra (mira el Botón 3).";
      }
      return "🧩 Hay un pequeño fallo de sintaxis en tu comando SQL. Fíjate en el Previsualizador en Tiempo Real y compáralo con la estructura del Botón 2 (UNION SELECT col1, col2 FROM tabla) y del Botón 3 (--).";
    }
    return "Revisa la consola de vista previa en vivo y apóyate en los 3 botones de ejemplo.";
  }

  function evaluateSearchQuery(rawInput) {
    // Si no hay comilla simple, búsqueda normal parametrizada sobre catalogo_museo (oculto = 0)
    if (!rawInput.includes("'")) {
      const needle = rawInput.toLowerCase();
      return DB_TABLES.catalogo_museo
        .filter(r => r.oculto === 0 && r.nombre_reliquia.toLowerCase().includes(needle))
        .map(r => [r.nombre_reliquia, r["año_hallazgo"]]);
    }

    // Construimos la consulta completa y procesamos comentarios (--)
    const fullQuery = `SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo WHERE nombre_reliquia LIKE '%${rawInput}%' AND oculto = 0`;
    const commentPos = fullQuery.indexOf("--");
    const activeSql = (commentPos !== -1 ? fullQuery.slice(0, commentPos) : fullQuery).trim();

    if (activeSql.includes("#")) {
      throw new Error('unrecognized token: "#"');
    }

    // Comprobar si las comillas simples están balanceadas en la parte activa
    const singleQuotes = (activeSql.match(/'/g) || []).length;
    if (singleQuotes % 2 !== 0) {
      throw new Error("unrecognized token: \"' AND oculto = 0\" (unclosed string literal)");
    }

    // Extraer lo que hay antes y después de cerrar la primera comilla del LIKE '%...
    const qIdx = rawInput.indexOf("'");
    const likePrefix = rawInput.slice(0, qIdx);
    const afterQuoteRaw = rawInput.slice(qIdx + 1);
    const cIdx = afterQuoteRaw.indexOf("--");
    const injectedRaw = (cIdx !== -1 ? afterQuoteRaw.slice(0, cIdx) : afterQuoteRaw).trim();

    // Filas base del lado izquierdo del SELECT (catalogo_museo)
    let leftRows = [];
    const needle = likePrefix.replace(/%/g, "").toLowerCase();
    const hasOrTrue = /OR\s+('1'\s*=\s*'1'|1\s*=\s*1|TRUE|oculto\s*=\s*1)/i.test(injectedRaw);
    const keepsOcultoFilter = (commentPos === -1);

    DB_TABLES.catalogo_museo.forEach(r => {
      if (keepsOcultoFilter && r.oculto !== 0 && !hasOrTrue) return;
      const matchesLike = needle === "" ? (rawInput.startsWith("%'") || likePrefix.includes("%")) : r.nombre_reliquia.toLowerCase().includes(needle);
      if (matchesLike || hasOrTrue) {
        leftRows.push([r.nombre_reliquia, r["año_hallazgo"]]);
      }
    });

    // ¿Hay un UNION SELECT?
    const unionIdx = injectedRaw.search(/\bUNION\b/i);
    if (unionIdx === -1) {
      // Si metió texto suelto tras la comilla que no es comentario ni operador válido
      if (injectedRaw !== "" && !/^(AND|OR|ORDER\s+BY|LIMIT)\b/i.test(injectedRaw)) {
        throw new Error(`near "${injectedRaw.split(/\s+/)[0]}": syntax error`);
      }
      return leftRows;
    }

    const afterUnion = injectedRaw.slice(unionIdx).replace(/^UNION(\s+ALL)?\s+/i, "").trim();
    if (!/^SELECT\b/i.test(afterUnion)) {
      throw new Error('near "UNION": syntax error (expected SELECT after UNION)');
    }

    const afterSelect = afterUnion.replace(/^SELECT\s+/i, "").trim();
    const fromMatch = afterSelect.match(/\bFROM\s+([a-zA-Z0-9_]+)(.*)$/i);
    if (!fromMatch) {
      throw new Error('syntax error: missing FROM table_name in UNION SELECT');
    }

    const colsPart = afterSelect.slice(0, fromMatch.index).trim();
    const tableName = fromMatch[1].trim().toLowerCase();

    const tablesMap = {
      catalogo_museo: DB_TABLES.catalogo_museo,
      donaciones_alumnos: DB_TABLES.donaciones_alumnos,
      capsula_1976: getCapsulaTable()
    };

    if (!tablesMap[tableName]) {
      throw new Error(`no such table: ${tableName}`);
    }

    const targetRows = tablesMap[tableName];
    let requestedCols = colsPart.split(",").map(c => c.trim()).filter(Boolean);

    if (requestedCols.length === 1 && requestedCols[0] === "*") {
      requestedCols = Object.keys(targetRows[0]);
    }

    if (requestedCols.length !== 2) {
      throw new Error("SELECTs to the left and right of UNION do not have the same number of result columns");
    }

    const validCols = Object.keys(targetRows[0]).map(k => k.toLowerCase());
    const colKeyMap = {};
    Object.keys(targetRows[0]).forEach(k => { colKeyMap[k.toLowerCase()] = k; });

    requestedCols.forEach(col => {
      const cleanCol = col.toLowerCase();
      const isLiteral = (col.startsWith("'") && col.endsWith("'")) || /^\d+$/.test(col) || cleanCol === "null";
      if (!isLiteral && !validCols.includes(cleanCol)) {
        throw new Error(`no such column: ${col}`);
      }
    });

    const unionRows = targetRows.map(row => {
      return requestedCols.map(col => {
        const cleanCol = col.toLowerCase();
        if (col.startsWith("'") && col.endsWith("'")) return col.slice(1, -1);
        if (/^\d+$/.test(col)) return col;
        if (cleanCol === "null") return "NULL";
        return row[colKeyMap[cleanCol]];
      });
    });

    return leftRows.concat(unionRows);
  }

  function renderLiveQuery() {
    const val = inputEl.value;

    if (val === "" && activePreset === "1") {
      previewEl.innerHTML =
        `<span class="sql-kw">SELECT</span> nombre_reliquia, año_hallazgo ` +
        `<span class="sql-kw">FROM</span> catalogo_museo ` +
        `<span class="sql-kw">WHERE</span> epoca = <span class="sql-str">'70s'</span> ` +
        `<span class="sql-kw">AND</span> oculto = 0`;
      feedbackEl.innerHTML = "";
      return;
    }
    if (val === "" && activePreset === "2") {
      previewEl.innerHTML =
        `<span class="sql-kw">SELECT</span> nombre_reliquia, año_hallazgo <span class="sql-kw">FROM</span> catalogo_museo <span class="sql-kw">WHERE</span> oculto = 0 ` +
        `<span class="sql-injected">UNION SELECT objeto_donado, autor FROM donaciones_alumnos</span>`;
      feedbackEl.innerHTML =
        ``;
      return;
    }

    const prefix =
      `<span class="sql-kw">SELECT</span> nombre_reliquia, año_hallazgo ` +
      `<span class="sql-kw">FROM</span> catalogo_museo ` +
      `<span class="sql-kw">WHERE</span> nombre_reliquia <span class="sql-kw">LIKE</span> <span class="sql-str">'%`;
    const suffixRaw = `%' AND oculto = 0`;
    const quoteIdx = val.indexOf("'");

    if (quoteIdx === -1) {
      const commentIdx = val.indexOf("--");
      previewEl.innerHTML =
        prefix +
        `<span class="sql-str">${escapeHtml(val)}</span>` +
        `<span class="sql-str">%'</span> <span class="sql-kw">AND</span> oculto = 0`;

      if (commentIdx !== -1) {
      } else {
      }
      return;
    }

    const beforeQuote = val.slice(0, quoteIdx);
    const afterQuote = val.slice(quoteIdx + 1);
    const commentIdx = afterQuote.indexOf("--");

    if (commentIdx !== -1) {
      const injectedCode = afterQuote.slice(0, commentIdx);
      const commentPart = afterQuote.slice(commentIdx);

      previewEl.innerHTML =
        prefix +
        `${escapeHtml(beforeQuote)}</span>` +
        `<span class="sql-quote-break" title="Has cerrado la comilla">'</span>` +
        `<span class="sql-injected">${escapeHtml(injectedCode)}</span>` +
        `<s class="sql-commented">${escapeHtml(commentPart)}${escapeHtml(suffixRaw)}</s>`;

      const upperInj = injectedCode.toUpperCase();
      if (upperInj.includes("UNION") && upperInj.includes("SELECT") && upperInj.includes("CAPSULA_1976")) {
        feedbackEl.innerHTML =
          `🚀 <strong>¡Inyección lista!</strong> Has cerrado la comilla <code>'</code>, has unido la tabla <code>capsula_1976</code> y has tachado el final con <code>--</code>. ¡Pulsa <strong>Buscar en el Archivo</strong>!`;
      } else {
        
      }
    } else {
      previewEl.innerHTML =
        prefix +
        `${escapeHtml(beforeQuote)}</span>` +
        `<span class="sql-quote-break" title="Has cerrado la comilla">'</span>` +
        `<span class="sql-injected">${escapeHtml(afterQuote)}</span>` +
        `<span class="sql-dangling">${escapeHtml(suffixRaw)}</span>`;
    }
  }

  function renderTableRows(rows) {
    flagBanner.style.display = "none";
    let detectedFlag = null;

    if (!rows || rows.length === 0) {
      resultsBody.innerHTML = `
        <tr>
          <td colspan="2" style="text-align:center; color:#94a3b8; padding:24px;">
            No se encontraron reliquias que coincidan con la búsqueda.
          </td>
        </tr>`;
      return;
    }

    resultsBody.innerHTML = rows.map(r => {
      const c0 = String(r[0] ?? "");
      const c1 = String(r[1] ?? "");
      const isFlag = c0.includes("INNOSOFT{") || c1.includes("INNOSOFT{");
      if (isFlag) {
        detectedFlag = c1.includes("INNOSOFT{") ? c1 : c0;
      }
      return `<tr class="${isFlag ? 'museum-flag-row' : ''}">
        <td>${escapeHtml(c0)}</td>
        <td class="museum-col-year">${escapeHtml(c1)}</td>
      </tr>`;
    }).join("");

    if (detectedFlag) {
      flagCode.textContent = detectedFlag;
      flagBanner.style.display = "block";
    }
  }

  function updatePresetButtons() {
    btn1.classList.toggle("active", activePreset === "1");
    btn2.classList.toggle("active", activePreset === "2");
    btn3.classList.toggle("active", activePreset === "3");
  }

  function applyPreset(p) {
    activePreset = p;
    updatePresetButtons();
    errorBox.style.display = "none";

    if (p === "1") {
      inputEl.value = "";
      const rows = DB_TABLES.catalogo_museo
        .filter(r => r.epoca === "70s" && r.oculto === 0)
        .map(r => [r.nombre_reliquia, r["año_hallazgo"]]);
      renderLiveQuery();
      renderTableRows(rows);
    } else if (p === "2") {
      inputEl.value = "";
      const rows = DB_TABLES.catalogo_museo
        .filter(r => r.oculto === 0)
        .map(r => [r.nombre_reliquia, r["año_hallazgo"]])
        .concat(DB_TABLES.donaciones_alumnos.map(d => [d.objeto_donado, d.autor]));
      renderLiveQuery();
      renderTableRows(rows);
    } else if (p === "3") {
      inputEl.value = "IBM%' -- ";
      renderLiveQuery();
      runUserSearch();
    }
  }

  function runUserSearch() {
    errorBox.style.display = "none";
    try {
      const rows = evaluateSearchQuery(inputEl.value);
      renderTableRows(rows);
    } catch (err) {
      renderTableRows([]);
      errorRaw.textContent = err.message;
      errorHelper.textContent = explainSqlError(err.message, inputEl.value);
      errorBox.style.display = "block";
    }
  }

  btn1.addEventListener("click", () => applyPreset("1"));
  btn2.addEventListener("click", () => applyPreset("2"));
  btn3.addEventListener("click", () => applyPreset("3"));

  btnReset.addEventListener("click", () => {
    activePreset = "";
    updatePresetButtons();
    tutorialEl.style.display = "none";
    errorBox.style.display = "none";
    inputEl.value = "";
    renderLiveQuery();
    runUserSearch();
  });

  inputEl.addEventListener("input", () => {
    if (activePreset === "1" || activePreset === "2") {
      activePreset = "";
      updatePresetButtons();
      tutorialEl.style.display = "none";
    }
    renderLiveQuery();
  });

  formEl.addEventListener("submit", (e) => {
    e.preventDefault();
    activePreset = "";
    updatePresetButtons();
    tutorialEl.style.display = "none";
    renderLiveQuery();
    runUserSearch();
  });

  // Inicializar vista por defecto
  renderLiveQuery();
  runUserSearch();

  // Sincronización del cronómetro individual de 20 min con el servidor CTFd
  (function initServerTimerSync() {
    const CHALLENGE_TITLE = "La Cápsula del Tiempo de 1976";
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
# MODO SERVIDOR AUTÓNOMO (SQLite + http.server por si se ejecuta con --serve)
# ==============================================================================

def init_challenge_db() -> None:
    """Inicializa la base de datos SQLite del Museo del 50º Aniversario."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("DROP TABLE IF EXISTS catalogo_museo")
    cur.execute("DROP TABLE IF EXISTS donaciones_alumnos")
    cur.execute("DROP TABLE IF EXISTS capsula_1976")

    cur.execute(
        """
        CREATE TABLE catalogo_museo (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_reliquia TEXT NOT NULL,
            año_hallazgo    TEXT NOT NULL,
            epoca           TEXT NOT NULL,
            oculto          INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    reliquias = [
        ("Tarjeta Perforada con mancha de café del primer examen de FORTRAN", "1976", "70s", 0),
        ("Manual original del terminal TeleType ASR-33 (subrayado con lágrimas)", "1978", "70s", 0),
        ("Cinta magnética de carrete abierto con apuntes de Ensamblador", "1979", "70s", 0),
        ("Ratón de bola IBM cuyo rodillo lleva sin limpiarse desde Naranjito '82", "1982", "80s", 0),
        ("Disquete flexible de 5¼ pulgadas con el Doom pirata en 4 partes", "1993", "90s", 0),
        ("Cable VGA del Salón de Actos que solo da imagen si lo doblas 47 grados", "2004", "00s", 0),
        ("Taza conmemorativa de las primeras Jornadas InnoSoft", "2012", "10s", 0),
        ("Prototipo IBM 5100 Experimental [RELIQUIA OCULTA EN EL SÓTANO]", "1977", "70s", 1),
    ]
    cur.executemany(
        "INSERT INTO catalogo_museo (nombre_reliquia, año_hallazgo, epoca, oculto) VALUES (?, ?, ?, ?)",
        reliquias,
    )

    cur.execute(
        """
        CREATE TABLE donaciones_alumnos (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            objeto_donado TEXT NOT NULL,
            autor         TEXT NOT NULL
        )
        """
    )
    donaciones = [
        ("Calculadora HP-35 Polaca Inversa que sobrevivió a Cálculo", "Promoción del 81"),
        ("Floppy de 3½ con prácticas de Turbo Pascal 7.0", "Antiguo Alumno '96"),
        ("Pen Drive de 128 MB encontrado en los laboratorios", "Becario Anónimo '05"),
    ]
    cur.executemany(
        "INSERT INTO donaciones_alumnos (objeto_donado, autor) VALUES (?, ?)",
        donaciones,
    )

    cur.execute(
        """
        CREATE TABLE capsula_1976 (
            codigo_secreto TEXT NOT NULL,
            contenido_flag TEXT NOT NULL
        )
        """
    )
    cur.executemany(
        "INSERT INTO capsula_1976 (codigo_secreto, contenido_flag) VALUES (?, ?)",
        [
            (
                "MANIFIESTO_FUNDACIONAL_1976",
                "«A los informáticos del año 2026: esperamos que ya no tengáis que programar haciendo agujeros en cartulinas.»",
            ),
            (
                "APERTURA_BODAS_DE_ORO_76",
                FLAG_CONTENT,
            ),
        ],
    )

    con.commit()
    con.close()


def explain_sql_error(error_msg: str, raw_input: str) -> str:
    """Traduce errores técnicos de SQLite a pistas súper claras para novatos."""
    err_lower = error_msg.lower()
    if "selects to the left and right of union do not have the same number of result columns" in err_lower:
        return (
            "📏 ¡Casi lo tienes! El error dice que las dos tablas del UNION no tienen el mismo número de columnas. "
            "Recuerda que la tabla del museo muestra 2 columnas, así que después de UNION SELECT debes escribir "
            "exactamente 2 columnas separadas por una coma (mira el Post-it amarillo: codigo_secreto, contenido_flag)."
        )
    if "no such table" in err_lower:
        return (
            "🗂️ La base de datos dice que esa tabla no existe. Revisa el Post-it amarillo del Archivero: "
            "la tabla secreta se llama exactamente capsula_1976."
        )
    if "no such column" in err_lower:
        return (
            "🏷️ Has puesto un nombre de columna que no existe en esa tabla. Revisa el Post-it amarillo: "
            "las dos columnas de la tabla capsula_1976 se llaman codigo_secreto y contenido_flag."
        )
    if "unrecognized token" in err_lower and "#" in raw_input:
        return (
            "💡 Has intentado comentar con '#', pero en esta base de datos los comentarios se hacen con "
            "dos guiones seguidos: -- (fíjate en el Botón 3 de ejemplo)."
        )
    if "syntax error" in err_lower or "unrecognized token" in err_lower:
        if "'" in raw_input and "--" not in raw_input:
            return (
                "✂️ Has cerrado la comilla simple ('), ¡bien hecho! Pero el final original de la consulta "
                "(%' AND oculto = 0) se ha quedado suelto y rompe la frase. Añade dos guiones (--) al final "
                "de tu texto para tachar y comentar lo que sobra (mira el Botón 3)."
            )
        return (
            "🧩 Hay un pequeño fallo de sintaxis en tu comando SQL. Fíjate en el Previsualizador en Tiempo Real "
            "y compáralo con la estructura del Botón 2 (UNION SELECT col1, col2 FROM tabla) y del Botón 3 (--)."
        )
    return "Revisa la consola de vista previa en vivo y apóyate en los 3 botones de ejemplo."


def execute_museum_request(preset: str = "", q: str = "", has_q_param: bool = False) -> dict:
    """Ejecuta la lógica del buscador del museo contra SQLite y devuelve los datos."""
    search_input = q
    tutorial_note = ""

    if preset == "1" and not has_q_param:
        query = "SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo WHERE epoca = '70s' AND oculto = 0"
        tutorial_note = (
            "📼 <strong>Explicación del Botón 1 (Consulta Básica):</strong> "
            "La base de datos ha ejecutado <code>SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo WHERE epoca = '70s'</code>. "
            "Fíjate en que siempre pedimos <strong>2 columnas</strong> separadas por coma."
        )
    elif preset == "2" and not has_q_param:
        query = (
            "SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo WHERE oculto = 0 "
            "UNION SELECT objeto_donado, autor FROM donaciones_alumnos"
        )
        tutorial_note = (
            "🤝 <strong>Explicación del Botón 2 (Cómo unir otra tabla con UNION):</strong> "
            "¡Mira la consola! Al añadir <code>UNION SELECT col1, col2 FROM otra_tabla</code>, la base de datos "
            "pega las filas de esa segunda tabla al final de la tabla del museo. "
            "¿Y si haces lo mismo con la tabla y las 2 columnas que menciona el <strong>Post-it amarillo</strong>?"
        )
    elif preset == "3" and not has_q_param:
        search_input = "IBM%' -- "
        query = (
            f"SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo "
            f"WHERE nombre_reliquia LIKE '%{search_input}%' AND oculto = 0"
        )
        tutorial_note = (
            "🔧 <strong>Explicación del Botón 3 (Cerrar comilla y tachar con <code>--</code>):</strong> "
            "Hemos buscado <code>IBM%' -- </code>. La comilla simple <code>'</code> cierra el texto antes de tiempo, y los dos guiones "
            "<code>--</code> <strong>tachan e ignoran</strong> el filtro <code>%' AND oculto = 0</code> del final (¡por eso acaba de aparecer "
            "en la tabla el <em>Prototipo IBM 5100 Oculto</em>!). Ahora combina este truco con el <code>UNION SELECT</code> del Botón 2."
        )
    else:
        query = (
            f"SELECT nombre_reliquia, año_hallazgo FROM catalogo_museo "
            f"WHERE nombre_reliquia LIKE '%{search_input}%' AND oculto = 0"
        )

    rows = []
    sql_error = None
    friendly_error = None
    flag_found = False

    if not os.path.exists(DB_PATH):
        init_challenge_db()

    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    cur = con.cursor()
    try:
        cur.execute(query)
        rows = cur.fetchall()
        for r in rows:
            if any(FLAG_CONTENT in str(cell) for cell in r):
                flag_found = True
                break
    except Exception as e:
        sql_error = str(e)
        friendly_error = explain_sql_error(sql_error, search_input)
    finally:
        con.close()

    return {
        "rows": rows,
        "search_input": search_input,
        "preset": preset,
        "tutorial_note": tutorial_note,
        "sql_error": sql_error,
        "friendly_error": friendly_error,
        "flag_found": flag_found,
        "flag_value": FLAG_CONTENT,
    }


def render_museum_html(ctx: dict = None) -> str:
    """Renderiza un documento HTML completo autónomo para el modo `--serve`."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Museo Retro-Informático 1976–2026 | 50º Aniversario ETSII - InnoSoft</title>
  <style>
    body {{
      background: radial-gradient(circle at top, #172554 0%, #0b0f19 55%);
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


class MuseumChallengeHTTPHandler(BaseHTTPRequestHandler):
    """Manejador HTTP autónomo para el modo `--serve`."""

    def do_GET(self):
        body = render_museum_html().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_str, *args):
        sys.stderr.write(f"[Museo-1976] {self.address_string()} - {format_str % args}\n")


def upsert_ctfd_Challenge_page() -> None:
    """
    Registra o actualiza la página interactiva del reto directamente en el modelo `Pages`
    de CTFd en las rutas `capsula-1976` y `capsula-1976/`, para que `localhost:8000/capsula-1976/`
    (y el túnel de Cloudflare) sirvan el reto directamente desde CTFd sin dar 404.
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
        # Siempre registramos/actualizamos la página interactiva `/capsula-1976` en CTFd
        upsert_ctfd_Challenge_page()

        existing = Challenges.query.filter_by(name=CHALLENGE_NAME).first()
        if existing is not None:
            existing.description = CHALLENGE_DESCRIPTION
            db.session.commit()
            print(f"[ok] '{CHALLENGE_NAME}' ya existía en la BD — descripción y ruta /{CHALLENGE_ROUTE} actualizadas.")
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

        # 3. Pistas (si las hay)
        for i, h in enumerate(HINTS, 1):
            db.session.add(Hints(
                challenge_id=challenge.id,
                title=h["title"],
                content=h["content"],
                cost=h["cost"],
                type="standard",
            ))
            print(f"    → Pista {i} (coste {h['cost']} pts)")
        db.session.commit()

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
    """Levanta en primer plano el servidor web del reto en http://localhost:5002."""
    print(f"[*] Inicializando base de datos del Museo 1976 en: {DB_PATH}")
    init_challenge_db()
    server = ThreadingHTTPServer(("0.0.0.0", CHALLENGE_PORT), MuseumChallengeHTTPHandler)
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
