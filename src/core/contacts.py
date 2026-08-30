"""
Libreta de contactos local: guarda las claves públicas (``PublicBundle``) de
las personas con las que el usuario quiere comunicarse.

Esto es deliberadamente simple y local (un fichero JSON en disco): SICN no
confía ciegamente en el servidor para decir "esta es la clave pública de
Bob" sin que el usuario la haya verificado antes (por ejemplo comparando la
huella digital por otro canal), tal y como recomienda docs/seguridad.md
("verificar la identidad de los destinatarios").
"""

from __future__ import annotations

import json
import os

from ..crypto.keys import PublicBundle


def load_contacts(path: str) -> dict[str, PublicBundle]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {name: PublicBundle.from_dict(bundle) for name, bundle in raw.items()}


def save_contacts(path: str, contacts: dict[str, PublicBundle]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({name: bundle.to_dict() for name, bundle in contacts.items()}, f, indent=2)


def add_contact(path: str, name: str, bundle: PublicBundle) -> None:
    contacts = load_contacts(path)
    contacts[name] = bundle
    save_contacts(path, contacts)
