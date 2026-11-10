#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
seeds/TEMPLATE_challenge.py
----------------------------
INSTRUCCIONES:
  1. Copia este fichero con el nombre de tu reto, p.ej:  seeds/xss_reflejado.py
  2. Rellena las secciones marcadas con  ← EDITAR
  3. Añade el reto a seeds/config.json
  4. Regístralo en manage_challenges.py  (CHALLENGE_KEY_MAP)
  5. Haz commit
"""

import sys
import os

SEEDS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SEEDS_DIR, ".."))

# ── ← EDITAR ──────────────────────────────────────────────────────────────────
# Clave única en snake_case — debe coincidir con la entrada en config.yml
CONFIG_KEY = "nombre_del_reto"
# ──────────────────────────────────────────────────────────────────────────────


def load_config() -> dict:
    import json
    config_path = os.path.join(SEEDS_DIR, "config.json")
    if not os.path.exists(config_path):
        return {"enabled": True, "state": "visible"}
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("challenges", {}).get(CONFIG_KEY, {"enabled": True, "state": "visible"})


from CTFd import create_app
from CTFd.models import Challenges, Flags, Hints, Solutions, Tags, db

# ==============================================================================
# ← EDITAR: datos del reto
# ==============================================================================

CHALLENGE_NAME     = "Nombre del Reto"          # ← nombre visible en CTFd
CHALLENGE_CATEGORY = "Web"                       # ← Web / Crypto / Forensics / Pwn / Misc / Reversing…
CHALLENGE_VALUE    = 100                         # ← puntos
CHALLENGE_ATTRIBUTION = "Written by Tu Nombre"  # ← autor

CHALLENGE_DESCRIPTION = """\
## Título del reto

Descripción del reto en **Markdown**. Explica el contexto y el objetivo
sin revelar la solución.

### Objetivo
Consigue la flag.

### Conexión
```
http://localhost:XXXX
```
"""

# La flag exacta que el participante debe enviar
FLAG_CONTENT = "CTF{aqui_va_tu_flag}"
FLAG_TYPE    = "static"   # "static" (exacta) | "regex" (expresión regular)
FLAG_DATA    = ""         # "" = case-sensitive | "case_insensitive"

# Pistas opcionales — elimina las que no necesites o añade más
HINTS = [
    {
        "title":   "Pista 1 — Orientación general",
        "content": "Una pista amplia que no desvela demasiado.",
        "cost":    0,    # gratis
    },
    {
        "title":   "Pista 2 — Más concreta",
        "content": "Una pista más específica.",
        "cost":    25,   # cuesta 25 puntos
    },
    # {
    #     "title":   "Pista 3 — Casi la solución",
    #     "content": "El payload exacto es...",
    #     "cost":    50,
    # },
]

# Etiquetas para filtrar retos en el panel
TAGS = ["web", "ejemplo"]   # ← cambia a las que correspondan

# Writeup/solución (estado "hidden" → solo el admin la ve hasta publicarla)
SOLUTION = """\
## Solución

Explica aquí paso a paso cómo se resuelve el reto.

```bash
# Comandos usados
```
"""

# ==============================================================================
# No es necesario editar nada por debajo de esta línea
# ==============================================================================


def challenge_exists(name: str) -> bool:
    return Challenges.query.filter_by(name=name).first() is not None


def seed():
    cfg = load_config()

    if not cfg.get("enabled", True):
        print(f"[skip] '{CHALLENGE_NAME}' desactivado en config.yml")
        return

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


if __name__ == "__main__":
    seed()
