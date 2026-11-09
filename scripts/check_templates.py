#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/check_templates.py
--------------------------
Comprueba que las plantillas del tema no tengan bloques Jinja duplicados
(p. ej. `{% block submit %}` dos veces), lo que provoca un error 500 al abrir
un reto y deja "muertos" los botones de la pestaña Desafíos.

Uso:  python scripts/check_templates.py
Sale con código 1 si encuentra algún problema.
"""
import collections
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = [
    ROOT / "CTFd/themes/core/templates/challenge.html",
    ROOT / "CTFd/themes/core/templates/challenges.html",
    ROOT / "CTFd/themes/core/templates/scoreboard.html",
    ROOT / "CTFd/themes/admin/templates/challenges/update.html",
]

ok = True
for path in TEMPLATES:
    text = path.read_text(encoding="utf-8")
    blocks = collections.Counter(re.findall(r"{%-?\s*block\s+(\w+)", text))
    dupes = {name: n for name, n in blocks.items() if n > 1}
    n_blocks = sum(blocks.values())
    n_end = len(re.findall(r"{%-?\s*endblock", text))
    n_if = len(re.findall(r"{%-?\s*if\b", text))
    n_endif = len(re.findall(r"{%-?\s*endif\b", text))
    problems = []
    if dupes:
        problems.append(f"bloques duplicados {dupes}")
    if n_blocks != n_end:
        problems.append(f"block/endblock descompensados ({n_blocks}/{n_end})")
    if n_if != n_endif:
        problems.append(f"if/endif descompensados ({n_if}/{n_endif})")
    rel = path.relative_to(ROOT)
    if problems:
        ok = False
        print(f"[ERROR] {rel}: " + "; ".join(problems))
    else:
        print(f"[ok]    {rel} ({len(text.splitlines())} lineas)")

sys.exit(0 if ok else 1)

