#!/usr/bin/env python3
"""
CLI del cliente SICN.

Ejemplos:
    python -m src.client.cli init --nombre Ana
    python -m src.client.cli whoami
    python -m src.client.cli register --server http://localhost:8000
    python -m src.client.cli add-contact --nombre Bob --fingerprint "ab12 cd34 ..." \\
        --x25519 <base64> --ed25519 <base64>
    python -m src.client.cli add-contact --nombre Bob --server http://localhost:8000 \\
        --fetch-fingerprint "ab12 cd34 ..."
    python -m src.client.cli send --a Bob --server http://localhost:8000 --mensaje "Hola"
    python -m src.client.cli inbox --server http://localhost:8000
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
from urllib.parse import urlsplit

import requests

from ..core.auth import canonical, check_bundle, context, proof_bytes
from .local import persist
from ..core.contacts import add_contact, load_contacts
from ..core.envelope import MAX_PLAINTEXT, Envelope, TamperedMessageError, open_message, seal_message
from ..crypto.keys import (
    Identity,
    PublicBundle,
    generate_identity,
    load_identity,
    pretty_fingerprint,
    save_identity,
)

DEFAULT_DATA_DIR = os.environ.get("SICN_DATA_DIR", "sicn_data")


def _paths(data_dir: str) -> dict:
    return {
        "identity": os.path.join(data_dir, "identity.enc"),
        "contacts": os.path.join(data_dir, "contacts.json"),
        "received": os.path.join(data_dir, "received"),
    }


def _ask_passphrase(confirm: bool = False) -> str:
    p1 = getpass.getpass("Contraseña de tu clave privada: ")
    if confirm:
        p2 = getpass.getpass("Repite la contraseña: ")
        if p1 != p2:
            print("Las contraseñas no coinciden.", file=sys.stderr)
            sys.exit(1)
    return p1


def cmd_init(args: argparse.Namespace) -> None:
    paths = _paths(args.data_dir)
    if os.path.exists(paths["identity"]):
        print(f"Ya existe una identidad en {paths['identity']}. No se ha sobrescrito.")
        return
    passphrase = _ask_passphrase(confirm=True)
    identity = generate_identity(args.nombre)
    save_identity(identity, paths["identity"], passphrase)
    print(f"Identidad creada para '{args.nombre}'.")
    print(f"Huella digital: {pretty_fingerprint(identity.fingerprint)}")
    print("Comparte tu huella digital por un canal de confianza para que otros puedan verificarte.")


def cmd_whoami(args: argparse.Namespace) -> None:
    paths = _paths(args.data_dir)
    passphrase = _ask_passphrase()
    identity = load_identity(paths["identity"], passphrase)
    print(f"Nombre: {identity.name}")
    print(f"Huella digital: {pretty_fingerprint(identity.fingerprint)}")


def request(method, server, path, **kwargs):
    response = requests.request(method, server.rstrip("/") + path, timeout=10, allow_redirects=False, **kwargs)
    if response.is_redirect:
        raise ValueError("El servidor intentó redirigir la solicitud")
    response.raise_for_status()
    return response.json()


def proof(server, identity, operation, payload):
    expected = {"fingerprint": identity.fingerprint, "operation": operation, "context": context(payload)}
    challenge = request("POST", server, "/challenge", json=expected)
    if set(challenge) != {*expected, "nonce", "audience", "expires_at"} or any(
        challenge[k] != v for k, v in expected.items()
    ):
        raise ValueError("El desafío no corresponde a la operación solicitada")
    signature = identity.ed25519_private.sign(proof_bytes(challenge))
    return {"nonce": challenge["nonce"], "signature": base64.b64encode(signature).decode("ascii")}


def cmd_register(args: argparse.Namespace) -> None:
    paths = _paths(args.data_dir)
    passphrase = _ask_passphrase()
    identity = load_identity(paths["identity"], passphrase)
    bundle = identity.public_bundle()
    payload = bundle.to_dict()
    request("POST", args.server, "/register", json={
        **payload, "proof": proof(args.server, identity, "register", payload),
    })
    print(f"Registrado en {args.server}. Huella digital: {pretty_fingerprint(bundle.fingerprint)}")


def cmd_add_contact(args: argparse.Namespace) -> None:
    paths = _paths(args.data_dir)

    if args.fetch_fingerprint:
        if not args.server:
            print("Necesitas --server para buscar la clave en el directorio.", file=sys.stderr)
            sys.exit(1)
        fp_clean = args.fetch_fingerprint.replace(" ", "")
        data = request("GET", args.server, f"/keys/{fp_clean}")
        bundle = PublicBundle(
            name=args.nombre or data["name"],
            fingerprint=fp_clean,
            x25519_public=data["x25519_public"],
            ed25519_public=data["ed25519_public"],
        )
    else:
        if not (args.fingerprint and args.x25519 and args.ed25519):
            print(
                "Debes indicar --fingerprint, --x25519 y --ed25519, o usar --fetch-fingerprint con --server.",
                file=sys.stderr,
            )
            sys.exit(1)
        bundle = PublicBundle(
            name=args.nombre,
            fingerprint=args.fingerprint.replace(" ", ""),
            x25519_public=args.x25519,
            ed25519_public=args.ed25519,
        )

    check_bundle(bundle)
    add_contact(paths["contacts"], args.nombre, bundle)
    print(f"Contacto '{args.nombre}' guardado. Verifica su huella digital antes de confiar en ella:")
    print(f"  {pretty_fingerprint(bundle.fingerprint)}")


def cmd_send(args: argparse.Namespace) -> None:
    paths = _paths(args.data_dir)
    passphrase = _ask_passphrase()
    identity = load_identity(paths["identity"], passphrase)

    contacts = load_contacts(paths["contacts"])
    if args.a not in contacts:
        print(f"No conozco al contacto '{args.a}'. Añádelo primero con add-contact.", file=sys.stderr)
        sys.exit(1)
    recipient = contacts[args.a]

    filename = None
    if args.archivo:
        with open(args.archivo, "rb") as f:
            plaintext = f.read(MAX_PLAINTEXT + 1)
        filename = os.path.basename(args.archivo)
    else:
        if args.mensaje is None:
            print("Indica --mensaje \"texto\" o --archivo ruta.", file=sys.stderr)
            sys.exit(1)
        plaintext = args.mensaje.encode("utf-8")

    envelope = seal_message(identity, recipient, plaintext, filename=filename)

    request("POST", args.server, "/messages", json=envelope.to_dict())
    print(f"Mensaje cifrado y enviado a '{args.a}'.")


def cmd_inbox(args: argparse.Namespace) -> None:
    paths = _paths(args.data_dir)
    passphrase = _ask_passphrase()
    identity = load_identity(paths["identity"], passphrase)
    contacts = load_contacts(paths["contacts"])
    contacts_by_fp = {c.fingerprint: c for c in contacts.values()}

    path = f"/messages/{identity.fingerprint}"
    after = 0
    while True:
        body = {"after": after}
        page = request("POST", args.server, path, json={**body, "proof": proof(args.server, identity, "inbox", body)})
        if not page["messages"] and after == 0:
            print("No hay mensajes nuevos.")
        for item in page["messages"]:
            raw = item["envelope"]
            digest = context(raw)
            persist(os.path.join(args.data_dir, "inbox"), digest + ".json", canonical(raw))
            envelope = Envelope.from_dict(raw)
            sender = contacts_by_fp.get(envelope.sender_fp)
            if sender is None:
                print("[AVISO] Remitente desconocido. Sobre guardado sin confirmar.")
                continue
            try:
                plaintext = open_message(identity, sender, envelope)
            except TamperedMessageError:
                print("[ALERTA] Sobre no verificable. Se conserva sin confirmar.")
                continue
            if envelope.filename:
                name = digest + "-" + envelope.filename
                persist(paths["received"], name, plaintext)
                print(f"Adjunto guardado: {name}")
            else:
                print(f"{sender.name}: {plaintext.decode('utf-8', errors='replace')}")
            ack = {"id": item["id"]}
            request("POST", args.server, path + "/ack", json={**ack, "proof": proof(args.server, identity, "ack", ack)})
        after = page["next_after"]
        if after is None:
            break


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cliente SICN: mensajería cifrada de extremo a extremo.")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Carpeta local de datos (por defecto: sicn_data)")
    sub = parser.add_subparsers(dest="comando", required=True)

    p_init = sub.add_parser("init", help="Genera una nueva identidad local.")
    p_init.add_argument("--nombre", required=True)
    p_init.set_defaults(func=cmd_init)

    p_whoami = sub.add_parser("whoami", help="Muestra tu nombre y huella digital.")
    p_whoami.set_defaults(func=cmd_whoami)

    p_register = sub.add_parser("register", help="Publica tus claves públicas en un servidor.")
    p_register.add_argument("--server", required=True)
    p_register.set_defaults(func=cmd_register)

    p_contact = sub.add_parser("add-contact", help="Añade la clave pública de un contacto.")
    p_contact.add_argument("--nombre", required=True)
    p_contact.add_argument("--fingerprint")
    p_contact.add_argument("--x25519")
    p_contact.add_argument("--ed25519")
    p_contact.add_argument("--server")
    p_contact.add_argument("--fetch-fingerprint", help="Busca esta huella digital en --server en vez de pegar las claves a mano.")
    p_contact.set_defaults(func=cmd_add_contact)

    p_send = sub.add_parser("send", help="Envía un mensaje o archivo cifrado.")
    p_send.add_argument("--a", required=True, help="Nombre del contacto destinatario.")
    p_send.add_argument("--server", required=True)
    p_send.add_argument("--mensaje")
    p_send.add_argument("--archivo")
    p_send.set_defaults(func=cmd_send)

    p_inbox = sub.add_parser("inbox", help="Recoge, verifica y descifra los mensajes pendientes.")
    p_inbox.add_argument("--server", required=True)
    p_inbox.set_defaults(func=cmd_inbox)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        server = getattr(args, "server", None)
        if server:
            url = urlsplit(server)
            if (not url.hostname or url.username or url.password or url.query or url.fragment
                or (url.scheme != "https" and not (
                    url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
                ))):
                raise ValueError("Usa HTTPS, salvo HTTP hacia localhost")
        args.func(args)
    except requests.RequestException as exc:
        status = exc.response.status_code if exc.response is not None else None
        parser.exit(1, f"Error de comunicación con el servidor (HTTP {status}).\n" if status
                    else "No se pudo conectar con el servidor.\n")
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
