#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
seeds/sql_challenge.py
----------------------
Reto Web SQL Injection (UNION SQLi "Con Ruedines"):
  🕹️ "La Cápsula del Tiempo de 1976"
  Jornadas InnoSoft — 50º Aniversario de los Estudios de Informática (ETSII)

Este archivo es 100% autónomo (todo en uno, sin ningún archivo extra):
  1. Actúa como seed de CTFd (basado en TEMPLATE_challenge.py) insertando el reto,
     la flag, las pistas, las etiquetas y la solución cuando se ejecuta en el contenedor.
  2. Contiene e inicia el servidor web vulnerable completo (en http://localhost:5002)
     usando únicamente la librería estándar de Python (sqlite3 + http.server) para que
     funcione en cualquier entorno sin instalar dependencias extra, con:
       - Los 3 botones de búsqueda rápida clicables (tutorial visual de SELECT, UNION y --)
       - El Post-it amarillo del Archivero con los nombres de tabla y columnas
       - El Previsualizador SQL en Tiempo Real que colorea la comilla (') y tacha (<s>)
         automáticamente el código comentado tras escribir (--)
       - Asistente traductor de errores SQL amigable para novatos sin conocimientos previos
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
👉 **[🕹️ Abrir el Catálogo del Museo (La Cápsula de 1976)](/capsula-1976/)**
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

La consulta resultante que ejecuta SQLite es:
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
# APLICACIÓN WEB DEL RETO (SQLite + Servidor HTTP autónomo en este mismo archivo)
# ==============================================================================

def init_challenge_db() -> None:
    """Inicializa la base de datos SQLite del Museo del 50º Aniversario."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("DROP TABLE IF EXISTS catalogo_museo")
    cur.execute("DROP TABLE IF EXISTS donaciones_alumnos")
    cur.execute("DROP TABLE IF EXISTS capsula_1976")

    # Tabla 1: Catálogo principal del museo
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

    # Tabla 2: Donaciones de antiguos alumnos (usada por el Botón 2 para enseñar UNION SELECT)
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

    # Tabla 3: La Cápsula del Tiempo de 1976 (Objetivo del reto)
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
    """Ejecuta la lógica del buscador del museo y devuelve los datos listos para renderizar."""
    search_input = q
    tutorial_note = ""

    # Lógica de los 3 botones de ejemplo clicables
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
        # Consulta intencionalmente vulnerable a SQL Injection
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

    # Abrimos SQLite en modo solo lectura para evitar que nadie borre ni modifique tablas
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


def render_museum_html(ctx: dict) -> str:
    """Renderiza el HTML completo del reto sin depender de motores de plantillas externos."""
    preset = ctx["preset"]
    search_input_escaped = html.escape(ctx["search_input"], quote=True)
    preset_json = json.dumps(preset)

    btn1_active = "active" if preset == "1" else ""
    btn2_active = "active" if preset == "2" else ""
    btn3_active = "active" if preset == "3" else ""

    tutorial_html = ""
    if ctx["tutorial_note"]:
        tutorial_html = f'<div class="tutorial-banner">{ctx["tutorial_note"]}</div>'

    flag_html = ""
    if ctx["flag_found"]:
        flag_html = f"""
        <div class="flag-celebration">
          <h2>🎉 ¡CÁPSULA DEL TIEMPO DE 1976 ABIERTA! 🎉</h2>
          <p>Has unido con éxito la tabla secreta del 50º Aniversario. Aquí tienes tu Flag para CTFd:</p>
          <div class="flag-code">{html.escape(ctx["flag_value"])}</div>
        </div>
        """

    error_html = ""
    if ctx["sql_error"]:
        error_html = f"""
        <div class="error-box">
          <h3>⚠️ Error devuelto por la Base de Datos SQLite:</h3>
          <div class="error-raw">{html.escape(ctx["sql_error"])}</div>
          <div class="error-helper">{html.escape(ctx["friendly_error"] or "")}</div>
        </div>
        """

    if ctx["rows"]:
        row_items = []
        for r in ctx["rows"]:
            col0 = str(r[0]) if len(r) > 0 else ""
            col1 = str(r[1]) if len(r) > 1 else ""
            is_flag = ("INNOSOFT{" in col0) or ("INNOSOFT{" in col1)
            row_cls = 'class="flag-row"' if is_flag else ""
            row_items.append(
                f"<tr {row_cls}>"
                f"<td>{html.escape(col0)}</td>"
                f'<td class="col-year">{html.escape(col1)}</td>'
                f"</tr>"
            )
        rows_html = "\n".join(row_items)
    else:
        rows_html = """
        <tr>
          <td colspan="2" style="text-align:center; color:#94a3b8; padding:24px;">
            No se encontraron reliquias que coincidan con la búsqueda.
          </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Museo Retro-Informático 1976–2026 | 50º Aniversario ETSII - InnoSoft</title>
  <style>
    :root {{
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
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: radial-gradient(circle at top, #172554 0%, var(--bg-dark) 55%);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      padding: 24px 16px 60px;
    }}
    .container {{
      max-width: 1120px;
      margin: 0 auto;
    }}
    .header {{
      background: linear-gradient(135deg, rgba(245,158,11,0.14), rgba(56,189,248,0.08));
      border: 1px solid rgba(245,158,11,0.45);
      border-radius: 14px;
      padding: 24px 28px;
      margin-bottom: 22px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
    }}
    .badge-50 {{
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
    }}
    .header h1 {{
      font-size: 1.75rem;
      color: #fff;
      margin-bottom: 8px;
    }}
    .header h1 span {{
      color: var(--gold-light);
    }}
    .story {{
      color: #cbd5e1;
      font-size: 0.94rem;
      line-height: 1.55;
    }}
    .story strong {{
      color: var(--gold-light);
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr 310px;
      gap: 20px;
      align-items: start;
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
    .panel {{
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.3);
      margin-bottom: 20px;
    }}
    .panel-title {{
      font-size: 0.95rem;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--cyan);
      margin-bottom: 14px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .quick-buttons-help {{
      font-size: 0.85rem;
      color: var(--muted);
      margin-bottom: 10px;
    }}
    .quick-buttons {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 18px;
    }}
    .btn-preset {{
      background: #1e293b;
      border: 1px solid #334155;
      color: #f8fafc;
      padding: 9px 14px;
      border-radius: 8px;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.18s;
      font-weight: 600;
    }}
    .btn-preset:hover {{
      border-color: var(--gold);
      background: rgba(245,158,11,0.15);
      transform: translateY(-1px);
    }}
    .btn-preset.active {{
      border-color: var(--gold);
      background: rgba(245,158,11,0.22);
      color: var(--gold-light);
    }}
    .search-row {{
      display: flex;
      gap: 10px;
      margin-bottom: 16px;
    }}
    .search-input {{
      flex: 1;
      background: var(--bg-console);
      border: 2px solid #334155;
      color: #fff;
      padding: 12px 16px;
      border-radius: 8px;
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 0.96rem;
      transition: border-color 0.2s;
    }}
    .search-input:focus {{
      outline: none;
      border-color: var(--cyan);
    }}
    .btn-search {{
      background: linear-gradient(135deg, #f59e0b, #d97706);
      color: #0b0f19;
      border: none;
      padding: 0 22px;
      border-radius: 8px;
      font-weight: 800;
      font-size: 0.92rem;
      cursor: pointer;
      transition: filter 0.15s;
      white-space: nowrap;
    }}
    .btn-search:hover {{
      filter: brightness(1.1);
    }}
    .btn-reset {{
      background: transparent;
      border: 1px solid #475569;
      color: var(--muted);
      padding: 0 14px;
      border-radius: 8px;
      font-size: 0.84rem;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
    }}
    .btn-reset:hover {{
      color: #fff;
      border-color: #94a3b8;
    }}
    .console-box {{
      background: var(--bg-console);
      border: 1px solid #1e293b;
      border-left: 4px solid var(--cyan);
      border-radius: 8px;
      padding: 14px 16px;
      font-family: 'Consolas', 'Courier New', monospace;
    }}
    .console-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.76rem;
      color: var(--muted);
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .console-live-dot {{
      color: var(--green);
      font-weight: bold;
    }}
    .sql-preview {{
      font-size: 0.94rem;
      line-height: 1.55;
      word-break: break-all;
      color: #93c5fd;
    }}
    .sql-kw {{ color: #c084fc; font-weight: bold; }}
    .sql-str {{ color: #fde047; }}
    .sql-quote-break {{
      background: rgba(239,68,68,0.28);
      color: #fca5a5;
      padding: 1px 4px;
      border-radius: 4px;
      font-weight: bold;
    }}
    .sql-injected {{
      color: #4ade80;
      font-weight: bold;
      background: rgba(34,197,94,0.12);
      padding: 1px 4px;
      border-radius: 4px;
    }}
    .sql-commented {{
      color: #64748b !important;
      text-decoration: line-through;
      opacity: 0.75;
    }}
    .sql-dangling {{
      color: #f87171;
      text-decoration: wavy underline #ef4444;
    }}
    .live-feedback {{
      margin-top: 10px;
      padding-top: 9px;
      border-top: 1px dashed #1e293b;
      font-size: 0.83rem;
      color: #cbd5e1;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }}
    .tutorial-banner {{
      margin-top: 14px;
      background: rgba(56,189,248,0.1);
      border: 1px solid rgba(56,189,248,0.35);
      border-radius: 8px;
      padding: 12px 15px;
      font-size: 0.87rem;
      line-height: 1.5;
      color: #e0f2fe;
    }}
    .tutorial-banner code {{
      background: rgba(0,0,0,0.4);
      padding: 2px 6px;
      border-radius: 4px;
      color: var(--gold-light);
      font-family: 'Consolas', monospace;
    }}
    .postit {{
      background: #fef08a;
      color: #1c1917;
      padding: 20px 18px;
      border-radius: 4px 4px 14px 4px;
      box-shadow: 6px 8px 20px rgba(0,0,0,0.45);
      transform: rotate(1.3deg);
      font-family: 'Comic Sans MS', 'Segoe Print', 'Bradley Hand', cursive, sans-serif;
      border-top: 14px solid #facc15;
      margin-bottom: 18px;
    }}
    .postit h3 {{
      font-size: 0.95rem;
      color: #991b1b;
      margin-bottom: 10px;
      text-transform: uppercase;
      border-bottom: 1px dashed #ca8a04;
      padding-bottom: 5px;
    }}
    .postit p {{
      font-size: 0.88rem;
      line-height: 1.5;
      margin-bottom: 10px;
    }}
    .postit code {{
      background: rgba(180,83,9,0.16);
      color: #7c2d12;
      font-weight: 800;
      padding: 1px 5px;
      border-radius: 3px;
      font-family: 'Consolas', monospace;
    }}
    .cheat-card {{
      background: rgba(19,27,46,0.9);
      border: 1px dashed #334155;
      border-radius: 10px;
      padding: 16px;
      font-size: 0.83rem;
      color: var(--muted);
      line-height: 1.5;
    }}
    .cheat-card h4 {{
      color: var(--gold-light);
      margin-bottom: 8px;
      font-size: 0.88rem;
    }}
    .cheat-card ul {{
      padding-left: 16px;
    }}
    .cheat-card li {{
      margin-bottom: 6px;
    }}
    .cheat-card code {{
      color: #4ade80;
      font-family: 'Consolas', monospace;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 6px;
    }}
    th {{
      text-align: left;
      background: #0f172a;
      color: var(--gold-light);
      padding: 11px 14px;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      border-bottom: 2px solid var(--border);
    }}
    td {{
      padding: 12px 14px;
      border-bottom: 1px solid #1e293b;
      font-size: 0.92rem;
    }}
    tr:hover td {{
      background: rgba(255,255,255,0.02);
    }}
    .col-year {{
      font-family: 'Consolas', monospace;
      color: var(--cyan);
      font-weight: 600;
    }}
    .flag-row td {{
      background: rgba(34,197,94,0.16) !important;
      border-top: 2px solid var(--green);
      border-bottom: 2px solid var(--green);
      color: #fff;
      font-weight: bold;
    }}
    .flag-celebration {{
      background: linear-gradient(135deg, rgba(34,197,94,0.22), rgba(16,185,129,0.1));
      border: 2px solid var(--green);
      border-radius: 12px;
      padding: 18px 22px;
      margin-bottom: 18px;
      text-align: center;
      box-shadow: 0 0 30px rgba(34,197,94,0.25);
    }}
    .flag-celebration h2 {{
      color: #4ade80;
      font-size: 1.3rem;
      margin-bottom: 6px;
    }}
    .flag-code {{
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
    }}
    .error-box {{
      background: rgba(239,68,68,0.1);
      border: 1px solid var(--red);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 18px;
    }}
    .error-box h3 {{
      color: #f87171;
      font-size: 0.95rem;
      margin-bottom: 6px;
    }}
    .error-raw {{
      font-family: 'Consolas', monospace;
      font-size: 0.83rem;
      color: #fca5a5;
      background: rgba(0,0,0,0.35);
      padding: 8px 10px;
      border-radius: 6px;
      margin-bottom: 10px;
    }}
    .error-helper {{
      color: #fef08a;
      font-size: 0.88rem;
      line-height: 1.45;
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Cabecera 50º Aniversario -->
    <div class="header">
      <div class="badge-50">🎓 1976 – 2026 · 50º Aniversario de los Estudios de Informática · Jornadas InnoSoft ETSII</div>
      <h1>🕹️ Archivo Histórico: <span>La Cápsula del Tiempo de 1976</span></h1>
      <p class="story">
        Con motivo de las <strong>Bodas de Oro de los Estudios de Informática</strong> en las Jornadas InnoSoft,
        hemos digitalizado el catálogo de reliquias históricas de los sótanos de la ETSII. Cuenta la leyenda que los
        primeros catedráticos de 1976 guardaron una <strong>Cápsula del Tiempo con la Flag</strong> en la base de datos,
        pero el Archivero Jefe la ha movido a otra tabla para que no salga en el buscador público.
      </p>
    </div>

    <div class="grid">
      <!-- Columna Izquierda: Buscador, Consola en vivo y Resultados -->
      <div>
        <div class="panel">
          <div class="panel-title">🔎 Buscador de Reliquias del Museo (v1.976)</div>

          <p class="quick-buttons-help">
            👇 <strong>¿No sabes SQL?</strong> Pulsa estos 3 botones de búsqueda rápida y observa en la consola de abajo cómo habla el buscador con la base de datos:
          </p>
          <div class="quick-buttons">
            <a href="?preset=1" style="text-decoration:none;">
              <button type="button" class="btn-preset {btn1_active}">
                📼 Botón 1: Ver reliquias de los 70
              </button>
            </a>
            <a href="?preset=2" style="text-decoration:none;">
              <button type="button" class="btn-preset {btn2_active}">
                🤝 Botón 2: Incluir donaciones de antiguos alumnos
              </button>
            </a>
            <a href="?preset=3" style="text-decoration:none;">
              <button type="button" class="btn-preset {btn3_active}">
                🔧 Botón 3: Modo Prueba del Archivero (--)
              </button>
            </a>
          </div>

          <form method="GET" action="" id="search-form">
            <div class="search-row">
              <input
                type="text"
                id="search-input"
                name="q"
                class="search-input"
                placeholder="Busca una reliquia o inyecta tu comando SQL aquí..."
                value="{search_input_escaped}"
                autocomplete="off"
              >
              <button type="submit" class="btn-search">Buscar en el Archivo</button>
              <a href="?" class="btn-reset">Limpiar</a>
            </div>
          </form>

          <!-- Consola de Vista Previa en Tiempo Real -->
          <div class="console-box">
            <div class="console-header">
              <span>🖥️ Previsualizador de Consulta SQL en Tiempo Real (Debug Console)</span>
              <span class="console-live-dot">● EN VIVO</span>
            </div>
            <div id="sql-preview" class="sql-preview"></div>
            <div id="live-feedback" class="live-feedback"></div>
          </div>

          {tutorial_html}
        </div>

        <!-- Resultados o Errores -->
        <div class="panel">
          <div class="panel-title">🏛️ Resultados del Catálogo (2 Columnas)</div>

          {flag_html}
          {error_html}

          <table>
            <thead>
              <tr>
                <th style="width: 68%;">Columna 1: Reliquia / Código (`nombre_reliquia`)</th>
                <th style="width: 32%;">Columna 2: Año / Contenido (`año_hallazgo`)</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Columna Derecha: El Post-it Amarillo ("Ruedines") y Guía Rápida -->
      <div>
        <div class="postit">
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

        <div class="cheat-card">
          <h4>🧩 Resumen de Pistas Visuales</h4>
          <ul>
            <li>La tabla del museo siempre muestra <strong>2 columnas</strong>.</li>
            <li>Si escribes una comilla <code>'</code> en el buscador, <strong>cierras el texto</strong> y pasas a dar órdenes a la base de datos.</li>
            <li>El <strong>Botón 2</strong> te enseña cómo funciona <code>UNION SELECT col1, col2 FROM otra_tabla</code>.</li>
            <li>El <strong>Botón 3</strong> te enseña cómo <code>--</code> <strong>tacha e ignora</strong> el final de la frase que te estorba.</li>
          </ul>
        </div>
      </div>
    </div>
  </div>

  <script>
    (function() {{
      const inputEl = document.getElementById('search-input');
      const previewEl = document.getElementById('sql-preview');
      const feedbackEl = document.getElementById('live-feedback');
      const activePreset = {preset_json};

      function escapeHtml(str) {{
        return str
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
      }}

      function renderLiveQuery() {{
        const val = inputEl.value;

        if (val === '' && activePreset === '1') {{
          previewEl.innerHTML =
            `<span class="sql-kw">SELECT</span> nombre_reliquia, año_hallazgo ` +
            `<span class="sql-kw">FROM</span> catalogo_museo ` +
            `<span class="sql-kw">WHERE</span> epoca = <span class="sql-str">'70s'</span> ` +
            `<span class="sql-kw">AND</span> oculto = 0`;
          feedbackEl.innerHTML =
            `📼 <strong>Botón 1 activo:</strong> Consulta normal filtrando por los años 70. ¡Prueba ahora el <strong>Botón 2</strong> y el <strong>Botón 3</strong>!`;
          return;
        }}
        if (val === '' && activePreset === '2') {{
          previewEl.innerHTML =
            `<span class="sql-kw">SELECT</span> nombre_reliquia, año_hallazgo <span class="sql-kw">FROM</span> catalogo_museo <span class="sql-kw">WHERE</span> oculto = 0 ` +
            `<span class="sql-injected">UNION SELECT objeto_donado, autor FROM donaciones_alumnos</span>`;
          feedbackEl.innerHTML =
            `🤝 <strong>Botón 2 activo:</strong> ¡Fíjate en la parte verde! Con <code>UNION SELECT col1, col2 FROM tabla</code> hemos unido otra tabla distinta al resultado.`;
          return;
        }}

        const prefix =
          `<span class="sql-kw">SELECT</span> nombre_reliquia, año_hallazgo ` +
          `<span class="sql-kw">FROM</span> catalogo_museo ` +
          `<span class="sql-kw">WHERE</span> nombre_reliquia <span class="sql-kw">LIKE</span> <span class="sql-str">'%`;
        const suffixRaw = `%' AND oculto = 0`;

        const quoteIdx = val.indexOf("'");

        if (quoteIdx === -1) {{
          const commentIdx = val.indexOf("--");
          previewEl.innerHTML =
            prefix +
            `<span class="sql-str">${{escapeHtml(val)}}</span>` +
            `<span class="sql-str">%'</span> <span class="sql-kw">AND</span> oculto = 0`;

          if (commentIdx !== -1) {{
            feedbackEl.innerHTML =
              `💡 Has escrito <code>--</code>, pero sigue <strong>dentro de las comillas amarillas</strong> del texto. ` +
              `Escribe una comilla simple <code>'</code> al principio para salir del texto de búsqueda.`;
          }} else {{
            feedbackEl.innerHTML =
              `📝 <strong>Modo búsqueda normal:</strong> Todo lo que escribes está encerrado dentro de <code>'%...%'</code>. ` +
              `Prueba a escribir una comilla simple <code>'</code> para romper la cadena.`;
          }}
          return;
        }}

        const beforeQuote = val.slice(0, quoteIdx);
        const afterQuote = val.slice(quoteIdx + 1);
        const commentIdx = afterQuote.indexOf("--");

        if (commentIdx !== -1) {{
          const injectedCode = afterQuote.slice(0, commentIdx);
          const commentPart = afterQuote.slice(commentIdx);

          previewEl.innerHTML =
            prefix +
            `${{escapeHtml(beforeQuote)}}</span>` +
            `<span class="sql-quote-break" title="Has cerrado la comilla">'</span>` +
            `<span class="sql-injected">${{escapeHtml(injectedCode)}}</span>` +
            `<s class="sql-commented">${{escapeHtml(commentPart)}}${{escapeHtml(suffixRaw)}}</s>`;

          const upperInj = injectedCode.toUpperCase();
          if (upperInj.includes("UNION") && upperInj.includes("SELECT") && upperInj.includes("CAPSULA_1976")) {{
            feedbackEl.innerHTML =
              `🚀 <strong>¡Inyección lista!</strong> Has cerrado la comilla <code>'</code>, has unido la tabla <code>capsula_1976</code> y has tachado el final con <code>--</code>. ¡Pulsa <strong>Buscar en el Archivo</strong>!`;
          }} else {{
            feedbackEl.innerHTML =
              `✂️ <strong>¡Final tachado con éxito!</strong> Todo lo que va detrás de <code>--</code> ha quedado anulado. ` +
              `Ahora puedes escribir tu comando <code>UNION SELECT ... FROM ...</code> en la zona verde entre <code>'</code> y <code>--</code>.`;
          }}
        }} else {{
          previewEl.innerHTML =
            prefix +
            `${{escapeHtml(beforeQuote)}}</span>` +
            `<span class="sql-quote-break" title="Has cerrado la comilla">'</span>` +
            `<span class="sql-injected">${{escapeHtml(afterQuote)}}</span>` +
            `<span class="sql-dangling">${{escapeHtml(suffixRaw)}}</span>`;

          feedbackEl.innerHTML =
            `🔓 <strong>¡Comilla rota!</strong> Lo que escribas ahora en verde se ejecutará como código SQL. ` +
            `⚠️ Recuerda terminar tu frase con <code>--</code> para tachar el trozo rojo sobrante (<code>%' AND oculto = 0</code>).`;
        }}
      }}

      inputEl.addEventListener('input', renderLiveQuery);
      renderLiveQuery();
    }})();
  </script>
</body>
</html>
"""


class MuseumChallengeHTTPHandler(BaseHTTPRequestHandler):
    """Manejador HTTP autónomo (sin dependencias externas) para el reto SQLi."""

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        preset = params.get("preset", [""])[0]
        has_q = "q" in params
        q = params.get("q", [""])[0]

        ctx = execute_museum_request(preset=preset, q=q, has_q_param=has_q)
        body = render_museum_html(ctx).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_str, *args):
        # Log limpio en consola
        sys.stderr.write(f"[Museo-1976] {self.address_string()} - {format_str % args}\n")


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ensure_background_server() -> None:
    """Si el servidor del reto en el puerto 5002 no está activo, lo lanza en segundo plano."""
    if is_port_in_use(CHALLENGE_PORT):
        print(f"[=] Servidor del reto '{CHALLENGE_NAME}' ya activo en http://localhost:{CHALLENGE_PORT}")
        return
    try:
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        else:
            kwargs["start_new_session"] = True

        subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--serve"],
            **kwargs,
        )
        print(f"[+] Servidor web del reto iniciado en segundo plano en http://localhost:{CHALLENGE_PORT}")
    except Exception as exc:
        print(f"[!] No se pudo iniciar el servidor en segundo plano: {exc}")


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
        # Si se ejecuta fuera del contenedor de CTFd (p.ej. directamente en Windows),
        # levantamos directamente el servidor del reto para poder probarlo al instante.
        print(f"[i] Paquete CTFd no detectado en el entorno local. Iniciando servidor del reto en primer plano...")
        run_server()
        return

    # Asegura que el servidor web del reto esté levantado en segundo plano en el puerto 5002
    ensure_background_server()

    challenge_state = cfg.get("state", "visible")
    app = create_app()

    with app.app_context():
        if challenge_exists(CHALLENGE_NAME):
            print(f"[skip] '{CHALLENGE_NAME}' ya existe en la BD")
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
        help=f"Inicia únicamente el servidor web del reto en el puerto {CHALLENGE_PORT}",
    )
    args = parser.parse_args()

    if args.serve:
        run_server()
    else:
        seed()
