# Criptografía SICN

Implementación criptográfica, basada íntegramente en la librería
[`cryptography`](https://cryptography.io/) (primitivas estándar y
auditadas). No se implementa ningún algoritmo criptográfico propio.

- `keys.py` — Generación de identidad (X25519 + Ed25519), huella digital,
  guardado y carga de claves privadas cifradas en disco con contraseña.
- `symmetric.py` — Cifrado autenticado AES-256-GCM.
- `kdf.py` — Derivación de claves: HKDF-SHA256 (a partir de un secreto
  ECDH) y scrypt (a partir de una contraseña).

Ver [`docs/seguridad.md`](../../docs/seguridad.md) para el razonamiento de
diseño y las limitaciones conocidas.
