# tests/

Suite de tests automatizados (pytest).

- `test_crypto.py` — Primitivas criptográficas: cifrado/descifrado
  simétrico y detección de manipulación, derivación de claves,
  guardado/carga de identidad cifrada con contraseña.
- `test_envelope.py` — Protocolo de mensajería de extremo a extremo:
  cifrado, firma, verificación, detección de manipulación y de intentos
  de suplantación de identidad.
- `test_server.py` — API HTTP completa: registro, directorio de claves,
  envío y recogida de mensajes (usando `TestClient` de FastAPI, sin
  necesidad de levantar un servidor real).

Ejecutar:

```bash
pip install -r requirements-dev.txt
pytest -v
```
