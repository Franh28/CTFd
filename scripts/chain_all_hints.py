#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/chain_all_hints.py
--------------------------
Encadena automáticamente todas las pistas de todos los retos en la base de datos de CTFd.
Para cada reto:
  - Pista 1: Sin prerrequisitos (accesible directamente).
  - Pista 2: Requiere haber desbloqueado la Pista 1.
  - Pista 3: Requiere haber desbloqueado la Pista 2.
  - ...y así sucesivamente.

Uso:
  docker compose exec ctfd python scripts/chain_all_hints.py
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


def main():
    try:
        from CTFd import create_app
        from CTFd.models import Challenges, Hints, db
    except ModuleNotFoundError as e:
        print(f"[!] Error: Este script debe ejecutarse en el entorno de CTFd (ej. dentro del contenedor Docker). Detalle: {e}")
        return 1

    app = create_app()
    with app.app_context():
        challenges = Challenges.query.order_by(Challenges.id).all()
        if not challenges:
            print("[i] No se encontraron retos en la base de datos.")
            return 0

        print(f"[*] Procesando {len(challenges)} retos para encadenar sus pistas...")
        total_chained = 0

        for chal in challenges:
            # Ordenamos las pistas por coste ascendente y luego por ID
            hints = Hints.query.filter_by(challenge_id=chal.id).order_by(Hints.cost.asc(), Hints.id.asc()).all()
            if not hints:
                print(f"  • Reto #{chal.id} ({chal.name}): 0 pistas")
                continue

            prev_id = None
            for idx, hint in enumerate(hints):
                if prev_id is None:
                    # Primera pista: sin prerrequisitos
                    hint.requirements = None
                else:
                    # Pistas siguientes: requieren la pista inmediatamente anterior
                    hint.requirements = {"prerequisites": [prev_id]}
                prev_id = hint.id

            db.session.commit()
            total_chained += len(hints)
            chain_str = " -> ".join([f"Pista {h.id} (coste {h.cost})" for h in hints])
            print(f"  ✔ Reto #{chal.id} ({chal.name}): {len(hints)} pistas encadenadas [{chain_str}]")

        print(f"\n[OK] ¡Listo! Se han encadenado {total_chained} pistas secuencialmente en {len(challenges)} retos.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

