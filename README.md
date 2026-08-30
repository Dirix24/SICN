# 🔐 SICN (SISC)

> **Sistema de Información Segura y Cifrada**

SICN es un sistema de mensajería cifrada de extremo a extremo, inspirado en
los servicios modernos de correo electrónico: el contenido se cifra y firma
en el dispositivo del remitente, viaja cifrado, y solo el destinatario
autorizado puede descifrarlo. El servidor almacena y transporta datos
cifrados, pero **nunca puede leerlos**.

Esta versión (0.2.0) es una implementación **funcional**, no solo un
esqueleto de documentación: hay criptografía real (basada en la librería
`cryptography`, no algoritmos caseros), un servidor HTTP, un cliente de
línea de comandos, y una batería de tests automatizados.

## 🔒 Cómo funciona

```text
Alice (cliente)                    Servidor SICN                Bob (cliente)
   │                                    │                            │
   │  1. Cifra y firma el mensaje       │                            │
   │     con la clave pública de Bob    │                            │
   │────────── POST /messages ────────▶│                            │
   │                                    │  guarda el sobre cifrado   │
   │                                    │  (nunca lo puede leer)     │
   │                                    │◀──── GET /messages/bob ────│
   │                                    │                            │
   │                                    │       2. Verifica firma    │
   │                                    │          y descifra        │
   │                                    │          localmente         │
```

1. **Identidad**: cada usuario genera localmente un par de claves X25519
   (para cifrar) y un par de claves Ed25519 (para firmar). La clave privada
   nunca sale de su dispositivo; se guarda en disco cifrada con una
   contraseña.
2. **Envío**: el cliente cifra el mensaje con AES-256-GCM usando una clave
   derivada (HKDF) de un intercambio Diffie-Hellman (X25519) efímero con la
   clave pública del destinatario, y firma el conjunto con Ed25519.
3. **Servidor**: recibe el "sobre" cifrado y lo deja en la cola del
   destinatario. No tiene ninguna clave privada de nadie: no puede leer el
   contenido ni falsificar la firma.
4. **Recepción**: el cliente destinatario recoge el sobre, verifica la
   firma (autenticidad + integridad) y lo descifra localmente.

## 🚀 Funcionalidades implementadas

- ✅ Generación y gestión de identidad (X25519 + Ed25519)
- ✅ Claves privadas cifradas en disco con contraseña (scrypt + AES-256-GCM)
- ✅ Cifrado y firma de mensajes de texto y archivos adjuntos
- ✅ Detección de manipulación (integridad) y de suplantación (autenticidad)
- ✅ Huella digital verificable (estilo PGP/Signal) para comprobar identidades
- ✅ Servidor HTTP (directorio de claves públicas + buzón de mensajes)
- ✅ Cliente de línea de comandos completo
- ✅ Tests automatizados (criptografía, protocolo y servidor)

### Previsto para el futuro (no implementado aún)

- Cliente de escritorio con interfaz gráfica y cliente web
- Extensión de navegador
- Múltiples dispositivos por identidad y revocación de claves
- Recuperación de cuenta
- Notificaciones push, búsqueda, gestión de contactos avanzada

## 🧩 Componentes

```text
SICN/
├── src/
│   ├── crypto/     Primitivas criptográficas (claves, cifrado, KDF)
│   ├── core/       Formato de mensaje (envelope) y contactos, lógica común
│   ├── client/     Cliente de línea de comandos
│   └── server/     Servidor HTTP (FastAPI) y almacenamiento (SQLite)
├── tests/          Tests automatizados (pytest)
├── examples/       Demo end-to-end sin servidor
└── docs/           Documentación de protocolo, arquitectura y seguridad
```

## 📦 Instalación

```bash
python -m venv .venv
source .venv/bin/activate   # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## ▶️ Uso rápido

### Demo sin servidor (para probar que la criptografía funciona)

```bash
python examples/demo.py
```

### Sistema completo (servidor + dos clientes)

```bash
# Terminal 1: levantar el servidor
uvicorn src.server.app:app --port 8000

# Terminal 2: Alice
export SICN_DATA_DIR=alice_data
python -m src.client.cli init --nombre Alice
python -m src.client.cli whoami                       # anota la huella digital
python -m src.client.cli register --server http://localhost:8000

# Terminal 3: Bob
export SICN_DATA_DIR=bob_data
python -m src.client.cli init --nombre Bob
python -m src.client.cli whoami                       # anota la huella digital
python -m src.client.cli register --server http://localhost:8000

# Alice añade a Bob como contacto (verificando su huella digital)
python -m src.client.cli add-contact --nombre Bob --server http://localhost:8000 \
    --fetch-fingerprint "<huella digital de Bob>"

# Alice le envía un mensaje
python -m src.client.cli send --a Bob --server http://localhost:8000 \
    --mensaje "Hola Bob, este mensaje es privado."

# Bob (en su propia sesión/SICN_DATA_DIR) añade a Alice y revisa su bandeja
python -m src.client.cli add-contact --nombre Alice --server http://localhost:8000 \
    --fetch-fingerprint "<huella digital de Alice>"
python -m src.client.cli inbox --server http://localhost:8000
```

También se puede enviar un archivo cifrado con `--archivo ruta/al/archivo`
en vez de `--mensaje`.

## 🧪 Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Los tests cubren: cifrado/descifrado simétrico y detección de manipulación,
derivación de claves, guardado/carga de identidad cifrada, el protocolo
completo de sellado/apertura de mensajes (incluyendo intentos de
suplantación y manipulación), y el servidor HTTP de extremo a extremo.

## ⚠️ Seguridad — léelo antes de usarlo con datos reales

- Se usan exclusivamente primitivas estándar de la librería `cryptography`
  (X25519, Ed25519, AES-256-GCM, HKDF, scrypt); no hay algoritmos
  criptográficos inventados.
- El diseño de cifrado es una construcción tipo ECIES con clave efímera por
  mensaje (secreto hacia adelante por mensaje), **no** es un "double
  ratchet" como el protocolo Signal: no tiene todas sus propiedades de
  seguridad de sesión.
- **Este proyecto no ha sido auditado.** No lo uses para proteger
  información realmente sensible sin antes hacer una auditoría de
  seguridad independiente. Ver [`docs/seguridad.md`](docs/seguridad.md).

## 📌 Estado

Versión actual: **0.2.0** — primera implementación funcional.

> 🔐 Privacidad primero. Seguridad siempre.
