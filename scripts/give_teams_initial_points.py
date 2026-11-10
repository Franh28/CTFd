#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/give_teams_initial_points.py
------------------------------------
Otorga el saldo inicial de 100 puntos a todos los equipos existentes
que todavía no lo tengan registrado en la base de datos de CTFd.

Uso:
  docker compose exec ctfd python scripts/give_teams_initial_points.py
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


def main():
    try:
        from CTFd import create_app
        from CTFd.models import Teams, Awards, db
        from CTFd.utils.scores import grant_initial_team_award
        from CTFd.cache import clear_standings
    except ModuleNotFoundError as e:
        print(f"[!] Error: Este script debe ejecutarse en el entorno de CTFd (ej. dentro del contenedor Docker). Detalle: {e}")
        return 1

    app = create_app()
    with app.app_context():
        teams = Teams.query.order_by(Teams.id).all()
        if not teams:
            print("[i] No se encontraron equipos en la base de datos.")
            return 0

        print(f"[*] Comprobando saldo inicial (100 pts) en {len(teams)} equipos...")
        granted_count = 0

        for t in teams:
            existing = Awards.query.filter_by(team_id=t.id, name="Saldo Inicial").first()
            if existing:
                print(f"  • Equipo #{t.id} ({t.name}): ya tiene Saldo Inicial de {existing.value} pts.")
            else:
                grant_initial_team_award(t, points=100)
                granted_count += 1
                print(f"  ✔ Equipo #{t.id} ({t.name}): ¡Otorgados +100 puntos iniciales!")

        clear_standings()
        print(f"\n[OK] Proceso completado. Se otorgaron 100 puntos iniciales a {granted_count} equipos nuevos/pendientes.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

