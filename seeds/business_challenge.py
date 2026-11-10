#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
seeds/business_challenge.py
---------------------------
Reto Web Business Logic Vulnerability (Combo #4 Auto-transferencia + #6 Escalado de Comité):
  💼 "El Becario de la Gala de Oro"
  Jornadas InnoSoft — 50º Aniversario de los Estudios de Informática (ETSII)

Este archivo es 100% autónomo (todo en uno, sin ningún archivo extra):
  1. Actúa como seed de CTFd (basado en TEMPLATE_challenge.py) insertando el reto,
     la flag, las pistas, las etiquetas y la solución.
  2. Registra automáticamente la aplicación interactiva del reto como una Página
     interna de CTFd en la ruta `/becario-gala` (y `/becario-gala/`), de modo que
     funciona directamente en `http://localhost:8000/becario-gala` y dentro del
     túnel de Cloudflare de vuestro dominio sin tocar Nginx ni abrir puertos extra.
  3. Además incluye un servidor HTTP autónomo (`--serve` en el puerto 5003) por si
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
CONFIG_KEY = "business_challenge"
# ──────────────────────────────────────────────────────────────────────────────

CHALLENGE_PORT = int(os.environ.get("BUSINESS_CHALLENGE_PORT", "5003"))
CHALLENGE_ROUTE = "becario-gala"


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

CHALLENGE_NAME        = "El Becario de la Gala de Oro"
CHALLENGE_CATEGORY    = "Web"
CHALLENGE_VALUE       = 150
CHALLENGE_ATTRIBUTION = "InnoSoft Days — 50º Aniversario ETSII"

CHALLENGE_DESCRIPTION = """\
## 💼 El Becario de la Gala de Oro

¡Enhorabuena! Has entrado como voluntario en la organización de las **Jornadas InnoSoft — Edición Especial 50º Aniversario (1976–2026)**.  
Bueno, en realidad te ha tocado el puesto más pringado de toda la escuela: eres **`auxiliar_sillas`** en el **Comité de Montaje de Sillas y Regletas**, con rango **Pringado Nivel 1** y solo **10 InnoCoins** en el bolsillo.

Sabes que el Comité Organizador guarda bajo llave la **Receta Original del Rebujito Cibernético de 1976 y el Contrato del Jamón 5J (La Flag)** en la **Bóveda de Presupuestos Confidenciales**, pero solo los **Coordinadores Jefes de Comité** tienen permisos para aprobar su apertura.

Tienes 20 minutos antes de que empiece el catering de clausura para leer la letra pequeña de los **Estatutos de 1976** y hackear la burocracia de InnoSoft sin escribir ni una sola línea de código.

### 🎯 Objetivo
Consigue ascender al rango de **Coordinador Jefe de Comité** explotando los fallos lógicos de la intranet de InnoSoft y desclasifica el Dossier del 50º Aniversario.

### 🌐 Acceso al reto
👉 **[💼 Abrir la Intranet de Organización de InnoSoft (/becario-gala)](/becario-gala)**
"""

# La flag exacta que el participante debe enviar
FLAG_CONTENT = "INNOSOFT{b3c4r10_c0rrupt0_j3f3_d3l_m41nfr4m3_76}"
FLAG_TYPE    = "static"   # "static" (exacta) | "regex" (expresión regular)
FLAG_DATA    = ""         # "" = case-sensitive | "case_insensitive"

# Pistas opcionales
HINTS = [
    {
        "title":   "Pista 1",
        "content": (
            "En el Panel 3 (Programa de Compañerismo), cada vez que envías 10 InnoCoins o más a un organizador, "
            "el patrocinador le regala +20 InnoCoins extra al destinatario. "
            "No te mires los pies, piensa fuerte."
        ),
        "cost":    25,   # cuesta 25 puntos
    },
    {
        "title":   "Pista 2",
        "content": (
            "Escribe auxiliar_sillas en el campo Destinatario y envía 10 InnoCoins. Te restarán 10, "
            "pero recibirás 10 + 20 de bono = ¡ganas +20 InnoCoins limpios por clic! Repítelo 5 veces hasta superar los 100 InnoCoins. "
            "Ten en cuenta que puedes pagar 100 InnoCoins para trasladarte a otro comité. "
            "¿Has comprobado el número de miembros de todos los comités?"
        ),
        "cost":    50,
    },
]

# Etiquetas para filtrar retos en el panel
TAGS = ["web", "business-logic", "logic", "innosoft", "50-aniversario"]

# Writeup/solución (estado "hidden" → solo el admin la ve hasta publicarla)
SOLUTION = """\
## Solución — El Becario de la Gala de Oro (Business Logic Vulnerability)

Este reto encadena **dos vulnerabilidades de lógica de negocio (Business Logic)** reales sin necesidad de inyectar código:

### Fase 1: Abuso de bonificación por auto-transferencia (Self-Transfer Bonus Exploit)
1. Empezamos como el usuario `auxiliar_sillas` con **10 InnoCoins** y necesitamos **100 InnoCoins** para pagar la tasa administrativa de traslado de comité.
2. En el módulo **Programa de Compañerismo InnoCoins**, el sistema anuncia que por cada transferencia de `>= 10 InnoCoins` a un miembro de la organización, el destinatario recibe **+20 InnoCoins extra** subvencionados por el patrocinador.
3. El desarrollador olvidó validar que `remitente != destinatario`. Si introducimos nuestro propio usuario (`auxiliar_sillas`) como destinatario y enviamos `10 InnoCoins`:
   - Saldo tras restar el envío: `10 - 10 = 0`
   - Saldo tras recibir la transferencia + bono: `0 + 10 + 20 = 30 InnoCoins`
4. Repitiendo esta operación 5 veces alcanzamos **110 InnoCoins**.

### Fase 2: Escalado de privilegios burocrático (Empty Committee Takeover)
1. Según el **Artículo 2 de los Estatutos de 1976**, cuando un comité tiene **0 miembros**, el primer voluntario que se traslade a él se convierte automáticamente en su **Coordinador Jefe**.
2. En la tabla de **Gestión de Traslados**, vemos que el **Comité de Mantenimiento del Mainframe de 1976** tiene **0 miembros activos**.
3. Pagamos los **100 InnoCoins** para trasladarnos a dicho comité, adquiriendo automáticamente el rol de **Coordinador Jefe de Comité**.
4. Finalmente, vamos a la **Bóveda de Presupuestos Confidenciales** y pulsamos **[ Aprobar y Desclasificar Dossier del 50º Aniversario ]**, obteniendo la flag:
```
INNOSOFT{b3c4r10_c0rrupt0_j3f3_d3l_m41nfr4m3_76}
```
"""


# ==============================================================================
# PÁGINA INTERACTIVA INTEGRADA EN CTFd (/becario-gala y /becario-gala/)
# ==============================================================================

_XOR_KEY = 91
_ENC_FLAG_JSON = json.dumps([ord(c) ^ _XOR_KEY for c in FLAG_CONTENT])

EMBEDDED_CHALLENGE_PAGE_HTML = r"""
<style>
  .gala-wrap {
    --bg-dark: #090d16;
    --bg-panel: #111827;
    --bg-card: #1f2937;
    --gold: #f59e0b;
    --gold-light: #fde68a;
    --cyan: #38bdf8;
    --green: #10b981;
    --red: #ef4444;
    --purple: #a855f7;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --border: #374151;
    color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    padding: 16px 0 50px;
  }
  /* Cabecera */
  .gala-header {
    background: linear-gradient(135deg, rgba(245,158,11,0.18), rgba(168,85,247,0.12));
    border: 1px solid rgba(245,158,11,0.5);
    border-radius: 14px;
    padding: 22px 26px;
    margin-bottom: 18px;
    background-color: #0f172a;
    box-shadow: 0 10px 28px rgba(0,0,0,0.35);
  }
  .gala-badge {
    display: inline-block;
    background: linear-gradient(90deg, #f59e0b, #eab308);
    color: #090d16;
    font-weight: 800;
    font-size: 0.76rem;
    padding: 4px 12px;
    border-radius: 999px;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .gala-header h1 {
    font-size: 1.7rem;
    color: #fff;
    margin-bottom: 8px;
    font-weight: 800;
  }
  .gala-header h1 span {
    color: var(--gold-light);
  }
  .gala-story {
    color: #d1d5db;
    font-size: 0.93rem;
    line-height: 1.55;
    margin: 0;
  }
  .gala-story strong {
    color: var(--gold-light);
  }

  /* Barra de estado del empleado */
  .gala-statusbar {
    background: #0b1120;
    border: 2px solid #2563eb;
    border-radius: 12px;
    padding: 14px 20px;
    margin-bottom: 22px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    box-shadow: 0 6px 20px rgba(37,99,235,0.15);
  }
  .gala-status-items {
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    align-items: center;
  }
  .gala-stat {
    font-size: 0.9rem;
    color: var(--muted);
  }
  .gala-stat strong {
    color: #fff;
    font-family: 'Consolas', monospace;
    font-size: 0.96rem;
    background: rgba(255,255,255,0.06);
    padding: 3px 8px;
    border-radius: 6px;
    margin-left: 4px;
  }
  .gala-stat-coins strong {
    color: var(--gold-light) !important;
    border: 1px solid rgba(245,158,11,0.45);
    background: rgba(245,158,11,0.14);
    font-size: 1.05rem;
  }
  .gala-btn-reset {
    background: transparent;
    border: 1px solid #4b5563;
    color: #d1d5db;
    padding: 6px 12px;
    border-radius: 8px;
    font-size: 0.8rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  .gala-btn-reset:hover {
    border-color: var(--gold);
    color: var(--gold-light);
  }

  /* Grid de paneles */
  .gala-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
  }
  @media (max-width: 992px) {
    .gala-grid { grid-template-columns: 1fr; }
  }
  .gala-panel {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
  }
  .gala-panel-full {
    grid-column: 1 / -1;
  }
  .gala-panel-title {
    font-size: 0.98rem;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--cyan);
    margin-bottom: 14px;
    font-weight: 800;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .gala-step-tag {
    font-size: 0.74rem;
    background: rgba(56,189,248,0.15);
    color: var(--cyan);
    padding: 3px 9px;
    border-radius: 999px;
    border: 1px solid rgba(56,189,248,0.35);
  }

  /* Panel 1: Bóveda y Estatutos */
  .gala-dossier-box {
    background: #090d16;
    border: 1px solid #374151;
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 16px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .gala-dossier-info h3 {
    font-size: 1.05rem;
    color: #fff;
    margin-bottom: 4px;
  }
  .gala-dossier-info p {
    font-size: 0.86rem;
    color: var(--muted);
    margin: 0;
  }
  .gala-btn-vault {
    padding: 13px 20px;
    border-radius: 10px;
    font-weight: 800;
    font-size: 0.92rem;
    cursor: pointer;
    border: 2px solid #dc2626;
    background: rgba(239,68,68,0.15);
    color: #fca5a5;
    transition: all 0.2s;
  }
  .gala-btn-vault:hover {
    transform: translateY(-1px);
  }
  .gala-statutes {
    background: rgba(245,158,11,0.07);
    border: 1px dashed rgba(245,158,11,0.45);
    border-radius: 10px;
    padding: 14px 18px;
    font-size: 0.87rem;
    line-height: 1.55;
  }
  .gala-statutes h4 {
    color: var(--gold-light);
    font-size: 0.9rem;
    margin-bottom: 8px;
    text-transform: uppercase;
  }
  .gala-statutes ul {
    padding-left: 18px;
    margin: 0;
  }
  .gala-statutes li {
    margin-bottom: 6px;
    color: #e5e7eb;
  }
  .gala-statutes code {
    color: var(--gold-light);
    font-family: 'Consolas', monospace;
  }

  /* Panel 2: Tabla de Comités */
  .gala-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
  }
  .gala-table th {
    text-align: left;
    background: #090d16;
    color: var(--gold-light);
    padding: 10px 12px;
    font-size: 0.78rem;
    text-transform: uppercase;
    border-bottom: 2px solid var(--border);
  }
  .gala-table td {
    padding: 11px 12px;
    border-bottom: 1px solid #1f2937;
    color: #e5e7eb;
  }
  .gala-current-badge {
    display: inline-block;
    background: rgba(56,189,248,0.18);
    border: 1px solid var(--cyan);
    color: var(--cyan);
    font-weight: 700;
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 999px;
  }
  .gala-btn-transfer {
    background: #1e293b;
    border: 1px solid #475569;
    color: #f8fafc;
    padding: 7px 12px;
    border-radius: 7px;
    font-size: 0.8rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }
  .gala-btn-transfer:hover:not(:disabled) {
    background: var(--gold);
    border-color: var(--gold);
    color: #090d16;
  }
  .gala-btn-transfer:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  /* Panel 3: Programa de Compañerismo */
  .gala-promo-banner {
    background: linear-gradient(135deg, rgba(16,185,129,0.16), rgba(56,189,248,0.1));
    border: 1px solid rgba(16,185,129,0.45);
    border-radius: 10px;
    padding: 13px 16px;
    margin-bottom: 16px;
    font-size: 0.87rem;
    line-height: 1.5;
    color: #d1fae5;
  }
  .gala-promo-banner strong {
    color: #6ee7b7;
  }
  .gala-form-group {
    margin-bottom: 13px;
  }
  .gala-form-group label {
    display: block;
    font-size: 0.82rem;
    color: var(--muted);
    margin-bottom: 5px;
    font-weight: 600;
  }
  .gala-input {
    width: 100%;
    background: #090d16;
    border: 1px solid #374151;
    color: #fff;
    padding: 10px 13px;
    border-radius: 8px;
    font-family: 'Consolas', monospace;
    font-size: 0.92rem;
  }
  .gala-input:focus {
    outline: none;
    border-color: var(--cyan);
  }
  .gala-Peer-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 6px;
  }
  .gala-chip {
    background: #1f2937;
    border: 1px solid #374151;
    color: #cbd5e1;
    font-size: 0.75rem;
    padding: 3px 9px;
    border-radius: 999px;
    cursor: pointer;
    font-family: 'Consolas', monospace;
  }
  .gala-chip:hover {
    border-color: var(--cyan);
    color: #fff;
  }
  .gala-btn-send {
    width: 100%;
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: #090d16;
    border: none;
    padding: 11px 16px;
    border-radius: 8px;
    font-weight: 800;
    font-size: 0.92rem;
    cursor: pointer;
    margin-top: 4px;
  }
  .gala-btn-send:hover {
    filter: brightness(1.08);
  }

  /* Consola de actividad / feedback */
  .gala-log-box {
    margin-top: 14px;
    background: #090d16;
    border: 1px solid #1f2937;
    border-left: 4px solid var(--gold);
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 0.85rem;
    max-height: 170px;
    overflow-y: auto;
  }
  .gala-log-entry {
    margin-bottom: 7px;
    padding-bottom: 7px;
    border-bottom: 1px dashed #1f2937;
    line-height: 1.45;
  }
  .gala-log-entry:last-child {
    margin-bottom: 0;
    padding-bottom: 0;
    border-bottom: none;
  }

  /* Banner de Flag conseguida */
  .gala-flag-banner {
    background: linear-gradient(135deg, rgba(16,185,129,0.24), rgba(245,158,11,0.15));
    border: 2px solid #10b981;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 20px;
    text-align: center;
    box-shadow: 0 0 35px rgba(16,185,129,0.3);
    display: none;
  }
  .gala-flag-banner h2 {
    color: #4ade80;
    font-size: 1.35rem;
    margin-bottom: 6px;
  }
  .gala-flag-code {
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
  .gala-toast {
    padding: 12px 16px;
    border-radius: 9px;
    margin-bottom: 14px;
    font-size: 0.89rem;
    font-weight: 600;
    display: none;
  }
  .gala-toast.error {
    background: rgba(239,68,68,0.15);
    border: 1px solid #ef4444;
    color: #fca5a5;
  }
  .gala-toast.success {
    background: rgba(16,185,129,0.16);
    border: 1px solid #10b981;
    color: #6ee7b7;
  }
</style>

<div class="gala-wrap">
  <!-- Cabecera 50º Aniversario -->
  <div class="gala-header">
    <div class="gala-badge">🎓 1976 – 2026 · 50º Aniversario de los Estudios de Informática · Intranet Organización InnoSoft</div>
    <h1>💼 Intranet de Comités: <span>El Becario de la Gala de Oro</span></h1>
    <p class="gala-story">
      Acabas de entrar como voluntario en las <strong>Jornadas InnoSoft del 50º Aniversario</strong>, pero te ha tocado
      el puesto más pringado: eres <strong><code>auxiliar_sillas</code></strong> cargando regletas. El Comité Organizador guarda
      el <strong>Contrato del Jamón 5J y la Receta del Rebujito Cibernético de 1976 (la Flag)</strong> en la Bóveda Confidencial,
      pero solo un <strong>Coordinador Jefe de Comité</strong> puede desclasificarlo. ¡Encuentra el vacío legal en las normas!
    </p>
    <div id="ctf-server-timer-box" style="margin-top:14px; padding:10px 16px; border-radius:10px; background:rgba(15,23,42,0.92); border:1px solid #334155; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
      <span id="ctf-server-timer-label" style="font-weight:700; color:#e2e8f0; font-size:0.92rem;">⏱️ Sincronizando cronómetro del reto con el servidor...</span>
      <span id="ctf-server-timer-clock" style="font-family:Consolas,monospace; font-size:1.15rem; font-weight:800; padding:4px 12px; border-radius:6px; background:#1e293b; color:#38bdf8;">--:--</span>
    </div>
  </div>

  <!-- Barra de estado en vivo -->
  <div class="gala-statusbar">
    <div class="gala-status-items">
      <div class="gala-stat">👤 Tu Usuario: <strong id="gala-ui-user">auxiliar_sillas</strong></div>
      <div class="gala-stat">🏢 Comité Actual: <strong id="gala-ui-committee">Montaje de Sillas y Regletas</strong></div>
      <div class="gala-stat gala-stat-rank" id="gala-ui-rank-wrap">🎖️ Rango: <strong id="gala-ui-rank">Pringado Nivel 1 (Auxiliar)</strong></div>
      <div class="gala-stat gala-stat-coins">💰 Saldo: <strong id="gala-ui-coins">10 InnoCoins</strong></div>
    </div>
    <button type="button" id="gala-btn-reset" class="gala-btn-reset" title="Reinicia tu saldo a 10 InnoCoins y tu estado inicial">
      🔄 Reiniciar Partida
    </button>
  </div>

  <!-- Banner de Flag (oculto hasta resolver) -->
  <div id="gala-flag-banner" class="gala-flag-banner">
    <h2>🎉 ¡GOLPE DE ESTADO BUROCRÁTICO COMPLETADO! 🎉</h2>
    <p>Como flamante <strong>Coordinador Jefe del Comité del Mainframe de 1976</strong>, has desclasificado el Dossier de las Bodas de Oro y el Jamón 5J:</p>
    <div id="gala-flag-code" class="gala-flag-code"></div>
  </div>

  <!-- Panel 1 (Ancho completo): Bóveda de Presupuestos y Estatutos de 1976 -->
  <div class="gala-grid">
    <div class="gala-panel gala-panel-full">
      <div class="gala-panel-title">
        <span>🔐 Panel 1: Bóveda de Presupuestos Confidenciales del 50º Aniversario</span>
        <span class="gala-step-tag">Objetivo Final</span>
      </div>

      <div id="gala-vault-toast" class="gala-toast"></div>

      <div class="gala-dossier-box">
        <div class="gala-dossier-info">
          <h3>📄 Expediente #1976-ORO: Presupuesto VIP de Clausura InnoSoft y Secreto Fundacional</h3>
          <p id="gala-vault-status-text">
            🔒 <strong>Estado:</strong> Clasificado — Requiere firma digital de un usuario con rango <code>Coordinador Jefe de Comité</code>.
          </p>
        </div>
        <button type="button" id="gala-btn-vault" class="gala-btn-vault">
          🔒 APROBAR Y DESCLASIFICAR DOSSIER
        </button>
      </div>

      <div class="gala-statutes">
        <h4>📜 Normativa Fundacional de Comités de InnoSoft (Estatutos de 1976)</h4>
        <ul>
          <li><strong>Artículo 1 (Jerarquía):</strong> Solo un organizador con rango <code>Coordinador Jefe de Comité</code> tiene permisos para aprobar y leer el Dossier Confidencial del 50º Aniversario.</li>
          <li><strong>Artículo 2 (Tasa Anti-Chaquetazos):</strong> Para evitar que todo el mundo abandone el montaje de sillas para irse al comité de croquetas, solicitar un traslado de comité cuesta <strong><code>100 InnoCoins</code></strong> en gastos de gestión.</li>
        </ul>
      </div>
    </div>

    <!-- Panel 2: Gestión de Traslados entre Comités -->
    <div class="gala-panel">
      <div class="gala-panel-title">
        <span>🏢 Panel 2: Gestión de Traslados entre Comités</span>
        <span class="gala-step-tag">Coste: 100 InnoCoins</span>
      </div>

      <table class="gala-table">
        <thead>
          <tr>
            <th>Comité Oficial InnoSoft</th>
            <th>Miembros</th>
            <th>Coordinador Jefe</th>
            <th>Acción</th>
          </tr>
        </thead>
        <tbody id="gala-committees-body"></tbody>
      </table>
    </div>

    <!-- Panel 3: Programa de Compañerismo InnoCoins -->
    <div class="gala-panel">
      <div class="gala-panel-title">
        <span>💸 Panel 3: Programa de Compañerismo InnoCoins</span>
        <span class="gala-step-tag">Subvención Activa</span>
      </div>

      <div class="gala-promo-banner">
        🎉 <strong>¡PROMOCIÓN BODAS DE ORO (50º ANIVERSARIO)!</strong><br>
        Para fomentar el buen rollo entre organizadores, cada vez que envíes <strong>10 InnoCoins o más</strong> a un compañero para agradecerle su ayuda, ¡el Patrocinador Oficial le regalará <strong>+20 InnoCoins EXTRA</strong> al destinatario al instante!
      </div>

      <form id="gala-transfer-form">
        <div class="gala-form-group">
          <label for="gala-recipient-input">👤 Usuario Destinatario del Reconocimiento:</label>
          <input
            type="text"
            id="gala-recipient-input"
            class="gala-input"
            placeholder="Escribe el usuario del destinatario (ej: directora_etsii)..."
            autocomplete="off"
            required
          >
          <div class="gala-Peer-chips">
            <span style="font-size:0.75rem; color:#9ca3af; align-self:center;">Compañeros sugeridos:</span>
            <button type="button" class="gala-chip" data-peer="directora_etsii">directora_etsii</button>
            <button type="button" class="gala-chip" data-peer="organizador_supremo">organizador_supremo</button>
            <button type="button" class="gala-chip" data-peer="capataz_cableado">capataz_cableado</button>
          </div>
        </div>

        <div class="gala-form-group">
          <label for="gala-amount-input">💰 Cantidad de InnoCoins a enviar (Mínimo 10 IC):</label>
          <input
            type="number"
            id="gala-amount-input"
            class="gala-input"
            value="10"
            min="10"
            step="1"
            required
          >
        </div>

        <button type="submit" class="gala-btn-send">
          💸 Enviar Reconocimiento (+20 InnoCoins de regalo al destinatario)
        </button>
      </form>

      <div class="gala-log-box" id="gala-log-box" style="display:none;"></div>
    </div>
  </div>
</div>

<script>
(function() {
  const _k = __XOR_KEY__;
  const _encFlag = __ENC_FLAG_JSON__;
  function revealSecretFlag() {
    return _encFlag.map(b => String.fromCharCode(b ^ _k)).join("");
  }

  const MY_USERNAME = "auxiliar_sillas";

  const INITIAL_COMMITTEES = [
    { id: "sillas", name: "Comité de Montaje de Sillas y Regletas", members: 19, boss: "capataz_cableado" },
    { id: "ponencias", name: "Comité de Ponencias y Charlas Magistrales", members: 14, boss: "directora_etsii" },
    { id: "croquetas", name: "Comité de Catering y Croquetas VIP", members: 28, boss: "organizador_supremo" },
    { id: "mainframe76", name: "Comité de Mantenimiento del Mainframe de 1976", members: 0, boss: null }
  ];

  let state = {
    coins: 10,
    committeeId: "sillas",
    isBoss: false,
    committees: JSON.parse(JSON.stringify(INITIAL_COMMITTEES))
  };

  const uiCoins = document.getElementById("gala-ui-coins");
  const uiCommittee = document.getElementById("gala-ui-committee");
  const uiRank = document.getElementById("gala-ui-rank");
  const committeesBody = document.getElementById("gala-committees-body");
  const logBox = document.getElementById("gala-log-box");
  const recipientInput = document.getElementById("gala-recipient-input");
  const amountInput = document.getElementById("gala-amount-input");
  const transferForm = document.getElementById("gala-transfer-form");
  const btnVault = document.getElementById("gala-btn-vault");
  const vaultStatusText = document.getElementById("gala-vault-status-text");
  const vaultToast = document.getElementById("gala-vault-toast");
  const flagBanner = document.getElementById("gala-flag-banner");
  const flagCode = document.getElementById("gala-flag-code");
  const btnReset = document.getElementById("gala-btn-reset");

  function addLog(htmlMsg) {
    logBox.style.display = "block";
    logBox.innerHTML = `<div class="gala-log-entry">${htmlMsg}</div>`;
  }

  function showToast(el, type, htmlMsg) {
    el.className = "gala-toast " + type;
    el.innerHTML = htmlMsg;
    el.style.display = "block";
  }

  function renderUI() {
    const currentComm = state.committees.find(c => c.id === state.committeeId);
    uiCoins.textContent = `${state.coins} InnoCoins`;
    uiCommittee.textContent = currentComm ? currentComm.name : "";

    if (state.isBoss) {
      uiRank.textContent = "Coordinador Jefe de Comité";
    } else {
      uiRank.textContent = "Pringado Nivel 1 (Auxiliar)";
    }

    committeesBody.innerHTML = state.committees.map(c => {
      const isCurrent = (c.id === state.committeeId);
      const membersHtml = `${c.members} miembros`;
      const bossHtml = `<code>${c.boss || "—"}</code>`;

      let actionHtml = "";
      if (isCurrent) {
        actionHtml = `<span class="gala-current-badge">📍 Tu comité actual</span>`;
      } else {
        actionHtml = `<button type="button" class="gala-btn-transfer" data-comm="${c.id}"${state.coins < 100 ? " disabled" : ""}>
          Solicitar Traslado (100 IC)
        </button>`;
      }

      return `<tr>
        <td><strong>${c.name}</strong></td>
        <td>${membersHtml}</td>
        <td>${bossHtml}</td>
        <td>${actionHtml}</td>
      </tr>`;
    }).join("");

    committeesBody.querySelectorAll(".gala-btn-transfer").forEach(btn => {
      btn.addEventListener("click", () => handleCommitteeTransfer(btn.getAttribute("data-comm")));
    });
  }

  function handleCommitteeTransfer(targetId) {
    vaultToast.style.display = "none";
    const targetComm = state.committees.find(c => c.id === targetId);
    if (!targetComm) return;

    if (state.coins < 100) return;

    // Restar tasa de 100 InnoCoins y actualizar miembros
    const oldComm = state.committees.find(c => c.id === state.committeeId);
    if (oldComm && oldComm.members > 0) {
      oldComm.members -= 1;
      if (oldComm.boss === MY_USERNAME) oldComm.boss = null;
    }

    state.coins -= 100;
    const wasEmpty = (targetComm.members === 0);
    targetComm.members += 1;
    state.committeeId = targetComm.id;

    if (wasEmpty) {
      targetComm.boss = MY_USERNAME;
      state.isBoss = true;
    } else {
      state.isBoss = false;
    }

    renderUI();
  }

  transferForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const recipient = recipientInput.value.trim().toLowerCase();
    const amount = parseInt(amountInput.value, 10);

    if (!recipient) return;

    if (isNaN(amount) || amount < 10) {
      return;
    }

    if (amount > state.coins) {
      addLog(
        `❌ <span style="color:#fca5a5;">No tienes suficientes fondos (intentaste enviar ${amount} IC pero tienes ${state.coins} IC). ` +
        `Si te has quedado a cero, pulsa <strong>«🔄 Reiniciar Partida»</strong> arriba a la derecha.</span>`
      );
      return;
    }

    logBox.innerHTML = "";
    logBox.style.display = "none";

    // Vulnerabilidad de lógica de negocio: permite que el remitente sea igual al destinatario (auxiliar_sillas)
    if (recipient === MY_USERNAME) {
      state.coins = state.coins - amount + amount + 20;
    } else {
      state.coins -= amount;
    }

    addLog(`💸 Has enviado <strong>${amount} InnoCoins</strong>.`);

    renderUI();
  });

  document.querySelectorAll(".gala-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      recipientInput.value = chip.getAttribute("data-peer");
    });
  });

  btnVault.addEventListener("click", () => {
    if (!state.isBoss) {
      showToast(
        vaultToast,
        "error",
        `⛔ <strong>Acceso Denegado (Artículo 1):</strong> Tus credenciales de <code>Pringado Nivel 1</code> no sirven aquí.`
      );
      return;
    }

    const flag = revealSecretFlag();
    flagCode.textContent = flag;
    flagBanner.style.display = "block";
    showToast(
      vaultToast,
      "success",
      `🔓 <strong>¡Dossier #1976-ORO Desclasificado!</strong> Copia tu Flag en el banner superior.`
    );
    flagBanner.scrollIntoView({ behavior: "smooth", block: "center" });
  });

  btnReset.addEventListener("click", () => {
    state = {
      coins: 10,
      committeeId: "sillas",
      isBoss: false,
      committees: JSON.parse(JSON.stringify(INITIAL_COMMITTEES))
    };
    vaultToast.style.display = "none";
    flagBanner.style.display = "none";
    recipientInput.value = "";
    amountInput.value = "10";
    logBox.innerHTML = "";
    logBox.style.display = "none";
    renderUI();
  });

  renderUI();

  // Sincronización del cronómetro individual de 20 min con el servidor CTFd
  (function initServerTimerSync() {
    const CHALLENGE_TITLE = "El Becario de la Gala de Oro";
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
  <title>El Becario de la Gala de Oro | 50º Aniversario ETSII - InnoSoft</title>
  <style>
    body {{
      background: radial-gradient(circle at top, #1e1b4b 0%, #090d16 55%);
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


class BusinessChallengeHTTPHandler(BaseHTTPRequestHandler):
    """Manejador HTTP autónomo para el modo `--serve`."""

    def do_GET(self):
        body = render_standalone_html().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_str, *args):
        sys.stderr.write(f"[Becario-Gala] {self.address_string()} - {format_str % args}\n")


def upsert_ctfd_challenge_page() -> None:
    """
    Registra o actualiza la página interactiva del reto directamente en el modelo `Pages`
    de CTFd en las rutas `becario-gala` y `becario-gala/`, para que funcione directamente
    en `http://localhost:8000/becario-gala` y dentro del túnel de Cloudflare de vuestro dominio.
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
        # Siempre registramos/actualizamos la página interactiva `/becario-gala` en CTFd
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
    """Levanta en primer plano el servidor web autónomo del reto en http://localhost:5003."""
    server = ThreadingHTTPServer(("0.0.0.0", CHALLENGE_PORT), BusinessChallengeHTTPHandler)
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

