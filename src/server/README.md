# SICN Server

Servidor encargado de comunicación, cuentas y almacenamiento.

- `app.py` — API HTTP (FastAPI): registro de claves públicas, consulta del
  directorio de claves, y depósito/recogida de mensajes cifrados.
- `storage.py` — Persistencia en SQLite: tabla `public_keys` (directorio,
  información pública) y tabla `mailbox` (cola de sobres cifrados
  pendientes de entrega, se vacía al recogerse).

El servidor no tiene acceso a ninguna clave privada y no puede leer el
contenido de los mensajes. Ver [`docs/seguridad.md`](../../docs/seguridad.md)
para las garantías y limitaciones exactas.

Arrancar en local:

```bash
uvicorn src.server.app:app --port 8000
```
