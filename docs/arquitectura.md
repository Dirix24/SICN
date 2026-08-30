# Arquitectura SICN

## Flujo principal

El mensaje se prepara, cifra y firma en el dispositivo del remitente
(`src/core/envelope.py::seal_message`). El servidor (`src/server/`) recibe
el sobre cifrado vía HTTP y lo almacena en una cola SQLite hasta que el
destinatario lo recoge. El destinatario verifica la firma y descifra
localmente (`src/core/envelope.py::open_message`).

```text
┌───────────────┐        HTTPS/JSON        ┌────────────────┐        HTTPS/JSON        ┌───────────────┐
│  Cliente A     │ ───────────────────────▶ │  Servidor SICN  │ ◀─────────────────────── │  Cliente B     │
│ (src/client)   │   POST /messages          │  (src/server)   │   GET /messages/{fp}     │ (src/client)   │
│                │                            │                 │                          │                │
│ claves privadas│                            │  SQLite:        │                          │ claves privadas│
│ NUNCA salen    │                            │  - directorio   │                          │ NUNCA salen    │
│ del dispositivo│                            │    de claves    │                          │ del dispositivo│
│                │                            │    públicas     │                          │                │
│                │                            │  - buzón de     │                          │                │
│                │                            │    sobres       │                          │                │
│                │                            │    cifrados     │                          │                │
└───────────────┘                            └────────────────┘                          └───────────────┘
```

## Componentes

- **`src/crypto/`** — Primitivas criptográficas de bajo nivel: generación
  y persistencia de claves (`keys.py`), cifrado simétrico AES-256-GCM
  (`symmetric.py`) y derivación de claves con HKDF/scrypt (`kdf.py`). Es la
  única parte del código que llama directamente a la librería
  `cryptography`.
- **`src/core/`** — Lógica común e independiente de transporte: el formato
  de sobre y las funciones de sellado/apertura (`envelope.py`), y la
  libreta de contactos local (`contacts.py`).
- **`src/client/`** — Interfaz de usuario (CLI): orquesta `crypto` y
  `core` para generar identidad, gestionar contactos, y enviar/recibir a
  través del servidor (`cli.py`).
- **`src/server/`** — Servicio HTTP (`app.py`, FastAPI) y su
  almacenamiento (`storage.py`, SQLite). Deliberadamente "tonto": solo ve
  datos ya cifrados y públicos (directorio de claves).

## Por qué el servidor no puede leer los mensajes

El servidor nunca tiene ninguna clave privada. El secreto que cifra cada
mensaje se deriva de un ECDH entre la clave privada X25519 del
**destinatario** (que nunca sale de su dispositivo) y una clave efímera
del remitente. Sin la clave privada del destinatario es computacionalmente
inviable derivar esa clave (seguridad de X25519 bajo el problema del
logaritmo discreto en curvas elípticas).

## Extensión futura

La interfaz `PublicBundle` / `Identity` en `src/crypto/keys.py` y el
`Envelope` en `src/core/envelope.py` son el contrato estable sobre el que
se podrían construir, sin cambiar el protocolo: un cliente de escritorio
con GUI, un cliente web, o una extensión de navegador — todos reutilizando
la misma lógica de `crypto/` y `core/`.
