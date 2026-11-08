#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
manage_challenges.py
--------------------
Script CLI para activar/desactivar retos en caliente (sin reiniciar Docker).

Actúa sobre dos niveles:
  1. La BD de CTFd → cambia el campo `state` del reto (visible/hidden)
  2. seeds/config.yml → sincroniza el estado para que persista en el siguiente arranque

Uso:
    python manage_challenges.py --list
    python manage_challenges.py --enable  "Broken Login"
    python manage_challenges.py --disable "Broken Login"
    python manage_challenges.py --toggle  "Broken Login"
    python manage_challenges.py --status  "Broken Login"

También puedes pasar varios retos a la vez:
    python manage_challenges.py --enable "Broken Login" "XSS Challenge"
"""

import argparse
import os
import sys

# Importa CTFd desde la raíz del proyecto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds", "config.json")

# Mapa nombre de reto → clave en config.json
# Añade aquí cada nuevo reto que crees.
CHALLENGE_KEY_MAP = {
    "Broken Login": "sqli_login",
    "La Cápsula del Tiempo de 1976": "sql_challenge",
    "El Becario de la Gala de Oro": "business_challenge",
    "El 4.99 de Don Severo": "xss_challenge",
}


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_yaml_config() -> dict:
    import json
    if not os.path.exists(CONFIG_PATH):
        return {"challenges": {}}
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f) or {"challenges": {}}


def save_yaml_config(data: dict) -> None:
    import json
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def sync_config(challenge_name: str, state: str) -> None:
    """Actualiza seeds/config.yml con el nuevo estado del reto."""
    key = CHALLENGE_KEY_MAP.get(challenge_name)
    if not key:
        return  # Reto no registrado en el mapa — no tocamos el config

    data = load_yaml_config()
    if "challenges" not in data:
        data["challenges"] = {}
    if key not in data["challenges"]:
        data["challenges"][key] = {}

    data["challenges"][key]["enabled"] = True       # siempre enabled si existe en BD
    data["challenges"][key]["state"] = state
    save_yaml_config(data)
    print(f"    → seeds/config.yml actualizado ({key}.state = {state})")


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_all_challenges(app):
    from CTFd.models import Challenges
    with app.app_context():
        return Challenges.query.order_by(Challenges.id).all()


def set_challenge_state(app, name: str, state: str) -> bool:
    """Cambia el campo `state` de un reto en la BD y actualiza su contador de 20 min. Devuelve True si lo encontró."""
    import datetime
    from CTFd.models import Challenges, db
    from CTFd.cache import clear_challenges

    with app.app_context():
        challenge = Challenges.query.filter_by(name=name).first()
        if not challenge:
            return False
        challenge.state = state
        if state == "visible":
            challenge.scheduled_at = datetime.datetime.utcnow()
        else:
            challenge.scheduled_at = None
        db.session.commit()
        clear_challenges()
        return True


def get_challenge_state(app, name: str):
    """Devuelve el estado actual ('visible'/'hidden') o None si no existe."""
    from CTFd.models import Challenges
    with app.app_context():
        challenge = Challenges.query.filter_by(name=name).first()
        if not challenge:
            return None
        return challenge.state


# ---------------------------------------------------------------------------
# Acciones
# ---------------------------------------------------------------------------

def cmd_list(app):
    challenges = get_all_challenges(app)
    if not challenges:
        print("No hay retos en la base de datos.")
        return

    print(f"\n{'ID':<5} {'Estado':<10} {'Categoría':<15} {'Nombre'}")
    print("─" * 55)
    for c in challenges:
        icon = "✅" if c.state == "visible" else "🔴"
        print(f"{c.id:<5} {icon} {c.state:<8} {c.category:<15} {c.name}")
    print()


def cmd_enable(app, names: list):
    for name in names:
        current = get_challenge_state(app, name)
        if current is None:
            print(f"[!] Reto '{name}' no encontrado en la BD.")
            continue
        if current == "visible":
            print(f"[=] '{name}' ya está visible.")
            continue
        ok = set_challenge_state(app, name, "visible")
        if ok:
            print(f"[✅] '{name}' → visible")
            sync_config(name, "visible")


def cmd_disable(app, names: list):
    for name in names:
        current = get_challenge_state(app, name)
        if current is None:
            print(f"[!] Reto '{name}' no encontrado en la BD.")
            continue
        if current == "hidden":
            print(f"[=] '{name}' ya está oculto.")
            continue
        ok = set_challenge_state(app, name, "hidden")
        if ok:
            print(f"[🔴] '{name}' → hidden")
            sync_config(name, "hidden")


def cmd_toggle(app, names: list):
    for name in names:
        current = get_challenge_state(app, name)
        if current is None:
            print(f"[!] Reto '{name}' no encontrado en la BD.")
            continue
        new_state = "hidden" if current == "visible" else "visible"
        set_challenge_state(app, name, new_state)
        icon = "✅" if new_state == "visible" else "🔴"
        print(f"[{icon}] '{name}': {current} → {new_state}")
        sync_config(name, new_state)


def cmd_status(app, names: list):
    for name in names:
        state = get_challenge_state(app, name)
        if state is None:
            print(f"[!] '{name}' — no encontrado en la BD")
        else:
            icon = "✅" if state == "visible" else "🔴"
            print(f"[{icon}] '{name}' → {state}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Gestión de retos CTFd en caliente",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python manage_challenges.py --list
  python manage_challenges.py --enable  "Broken Login"
  python manage_challenges.py --disable "Broken Login"
  python manage_challenges.py --toggle  "Broken Login"
  python manage_challenges.py --status  "Broken Login"
  python manage_challenges.py --enable  "Broken Login" "XSS Challenge"
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list",    action="store_true", help="Lista todos los retos y su estado")
    group.add_argument("--enable",  nargs="+", metavar="NOMBRE", help="Activa uno o más retos (visible)")
    group.add_argument("--disable", nargs="+", metavar="NOMBRE", help="Desactiva uno o más retos (hidden)")
    group.add_argument("--toggle",  nargs="+", metavar="NOMBRE", help="Alterna el estado de uno o más retos")
    group.add_argument("--status",  nargs="+", metavar="NOMBRE", help="Muestra el estado actual de un reto")

    args = parser.parse_args()

    from CTFd import create_app
    app = create_app()

    if args.list:
        cmd_list(app)
    elif args.enable:
        cmd_enable(app, args.enable)
    elif args.disable:
        cmd_disable(app, args.disable)
    elif args.toggle:
        cmd_toggle(app, args.toggle)
    elif args.status:
        cmd_status(app, args.status)


if __name__ == "__main__":
    main()
