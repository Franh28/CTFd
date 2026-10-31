#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
seeds/sqli_login.py
--------------------
Seed script que inserta el reto "Broken Login (SQLi)" en CTFd.

Ejecutado automáticamente por docker-entrypoint.sh en cada arranque.
Es idempotente: si el reto ya existe, no hace nada.
Lee seeds/config.yml para saber si debe ejecutarse y con qué estado.
"""

import sys
import os

# Garantiza que el paquete CTFd sea importable cuando se ejecuta como script
SEEDS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SEEDS_DIR, ".."))

# Clave de este reto en seeds/config.yml
CONFIG_KEY = "sqli_login"


def load_config() -> dict:
    """Lee seeds/config.json y devuelve la sección de este reto."""
    import json

    config_path = os.path.join(SEEDS_DIR, "config.json")
    if not os.path.exists(config_path):
        # Sin config → comportamiento por defecto: activado y visible
        return {"enabled": True, "state": "visible"}

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("challenges", {}).get(CONFIG_KEY, {"enabled": True, "state": "visible"})

from CTFd import create_app
from CTFd.models import (
    Challenges,
    Flags,
    Hints,
    Solutions,
    Tags,
    db,
)

# ---------------------------------------------------------------------------
# Contenido del reto
# ---------------------------------------------------------------------------

CHALLENGE_NAME = "Broken Login"
CHALLENGE_CATEGORY = "Web"
CHALLENGE_VALUE = 150
CHALLENGE_DESCRIPTION = """\
## 🔐 Broken Login

El equipo de desarrollo ha puesto en producción un panel de administración
con un sistema de login **casero**. Aseguran que es totalmente seguro.

Encuentra la forma de acceder **sin conocer la contraseña**.

### Objetivo
Consigue la flag accediendo al panel de administración.

### Conexión
El servicio está disponible en:
```
http://localhost:5001
```

> **Nota:** Puedes ejecutar el servidor tú mismo con:
> ```bash
> cd challenge_files/sqli_login
> pip install -r requirements.txt
> python app.py
> ```
"""

CHALLENGE_ATTRIBUTION = "Written by CTFd Admin"

# La flag real — debe coincidir con FLAG en challenge_files/sqli_login/app.py
FLAG_CONTENT = "CTF{sqli_0r_1_eq_1_byp4ss}"

HINTS = [
    {
        "title": "Pista 1 — ¿Qué hay detrás del login?",
        "content": (
            "El servidor usa SQL para comprobar tus credenciales. "
            "Intenta pensar en cómo se construye la consulta internamente."
        ),
        "cost": 0,
    },
    {
        "title": "Pista 2 — Caracteres especiales en SQL",
        "content": (
            "En SQL, el carácter `'` (comilla simple) cierra una cadena de texto. "
            "El `--` comenta todo lo que va después en la misma línea. "
            "¿Qué pasaría si tu usuario es `' OR 1=1 --`?"
        ),
        "cost": 25,
    },
    {
        "title": "Pista 3 — Payload exacto",
        "content": (
            "Introduce esto en el campo **usuario** (la contraseña puede ser cualquier cosa):\n"
            "```\n' OR 1=1 --\n```\n"
            "Esto hace que la condición SQL sea siempre verdadera y loguea al primer usuario "
            "de la tabla (el administrador)."
        ),
        "cost": 50,
    },
]

TAGS = ["sqli", "web", "authentication", "bypass"]

SOLUTION = """\
## Solución: SQL Injection con OR 1=1 --

### Vulnerabilidad
El servidor construye la consulta SQL concatenando directamente la entrada del usuario:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

### Payload
En el campo **usuario** introducimos:
```
' OR 1=1 --
```
La consulta resultante es:
```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'
```

### Explicación paso a paso
1. `'` → Cierra la cadena del username
2. `OR 1=1` → Añade una condición que siempre es **verdadera**
3. `--` → Comenta el resto de la query (incluyendo el `AND password`)

La query devuelve **todos los usuarios** (o el primero), ignorando por completo la contraseña.

### Corrección
Usar **consultas parametrizadas**:
```python
cur.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password)
)
```
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def challenge_exists(name: str) -> bool:
    return Challenges.query.filter_by(name=name).first() is not None


# ---------------------------------------------------------------------------
# Seed principal
# ---------------------------------------------------------------------------


def seed():
    cfg = load_config()

    if not cfg.get("enabled", True):
        print(f"[skip] Reto '{CHALLENGE_NAME}' desactivado en seeds/config.yml — omitiendo.")
        return

    challenge_state = cfg.get("state", "visible")

    app = create_app()

    with app.app_context():
        if challenge_exists(CHALLENGE_NAME):
            print(f"[skip] Reto '{CHALLENGE_NAME}' ya existe — nada que hacer.")
            return

        print(f"[+] Creando reto: {CHALLENGE_NAME} (estado: {challenge_state})")

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
        print(f"    → ID: {challenge.id}")

        # 2. Flag
        flag = Flags(
            challenge_id=challenge.id,
            content=FLAG_CONTENT,
            type="static",
            data="",
        )
        db.session.add(flag)
        db.session.commit()
        print(f"    → Flag: {FLAG_CONTENT}")

        # 3. Pistas
        for i, h in enumerate(HINTS, start=1):
            hint = Hints(
                challenge_id=challenge.id,
                title=h["title"],
                content=h["content"],
                cost=h["cost"],
                type="standard",
            )
            db.session.add(hint)
            print(f"    → Pista {i}: coste={h['cost']} pts")
        db.session.commit()

        # 4. Tags
        for tag_value in TAGS:
            tag = Tags(challenge_id=challenge.id, value=tag_value)
            db.session.add(tag)
        db.session.commit()
        print(f"    → Tags: {', '.join(TAGS)}")

        # 5. Solución / writeup (oculta)
        solution = Solutions(
            challenge_id=challenge.id,
            content=SOLUTION,
            state="hidden",
        )
        db.session.add(solution)
        db.session.commit()
        print("    → Solución añadida (hidden)")

        print(f"[ok] Reto '{CHALLENGE_NAME}' creado correctamente.")


if __name__ == "__main__":
    seed()
