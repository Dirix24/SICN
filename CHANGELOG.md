# Changelog

## 0.2.0

Primera implementación funcional (antes solo existía la documentación de
diseño).

- Módulo `crypto`: generación de identidad (X25519 + Ed25519), cifrado
  simétrico AES-256-GCM, derivación de claves (HKDF, scrypt), guardado de
  claves privadas cifradas en disco con contraseña.
- Módulo `core`: formato de mensaje (`Envelope`), sellado/apertura
  autenticados de extremo a extremo, libreta de contactos local.
- Módulo `server`: API HTTP (FastAPI) con directorio de claves públicas y
  buzón de mensajes cifrados (SQLite), sin acceso a ninguna clave privada.
- Módulo `client`: CLI completa (`init`, `whoami`, `register`,
  `add-contact`, `send`, `inbox`), con soporte de texto y archivos
  adjuntos.
- Suite de tests automatizados (`tests/`): cifrado/descifrado, detección
  de manipulación y de suplantación, flujo HTTP completo.
- Demo sin servidor (`examples/demo.py`) para verificar la criptografía
  rápidamente.
- Documentación (`README.md`, `docs/`) actualizada para describir el
  protocolo y el diseño de seguridad realmente implementados, incluyendo
  limitaciones honestas.

## 0.1.0

- Creación inicial de SISC/SICN.
- Arquitectura inicial.
- Documentación de seguridad.
- Estructura para cliente, servidor, extensión y criptografía (solo
  documentación, sin código).
