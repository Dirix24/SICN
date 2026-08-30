# Seguridad SICN

## Principios (se mantienen desde la v0.1.0)

1. No utilizar algoritmos criptográficos caseros para producción.
2. Utilizar algoritmos y bibliotecas criptográficas estándar.
3. Proteger las claves privadas.
4. Minimizar la información sensible almacenada en el servidor.
5. Autenticar los mensajes cuando corresponda.
6. Verificar la identidad de los destinatarios.
7. Realizar pruebas automatizadas.
8. Realizar auditorías de seguridad antes de producción.

## Cómo se aplican en esta implementación (v0.2.0)

| Principio | Implementación |
|---|---|
| Sin algoritmos caseros | Toda la criptografía usa la librería [`cryptography`](https://cryptography.io/) (X25519, Ed25519, AES-256-GCM, HKDF, scrypt). No hay ninguna primitiva implementada a mano. |
| Bibliotecas estándar | Ídem. |
| Proteger claves privadas | Nunca se transmiten. En disco se guardan cifradas con AES-256-GCM usando una clave derivada de la contraseña del usuario con scrypt (costoso de atacar por fuerza bruta). El fichero se crea con permisos `0600`. |
| Minimizar datos en el servidor | El servidor solo almacena: claves **públicas** (por definición no sensibles) y sobres cifrados en una cola que se vacía al entregarse (no queda histórico permanente). |
| Autenticar mensajes | Cada sobre va firmado con Ed25519 por el remitente; el destinatario verifica la firma antes de confiar en el contenido. |
| Verificar identidad | El cliente muestra la huella digital (fingerprint) de cada identidad en formato legible, para que los usuarios la comparen por un canal externo de confianza antes de añadir un contacto — como en PGP o Signal. `add-contact` obliga a fijar explícitamente la clave pública asociada a un nombre. |
| Pruebas automatizadas | `tests/test_crypto.py`, `tests/test_envelope.py`, `tests/test_server.py` — cubren cifrado/descifrado, manipulación, suplantación, y el flujo HTTP completo. |
| Auditoría antes de producción | **Pendiente.** Ver advertencia abajo. |

## Limitaciones conocidas (honestidad ante todo)

- **No es un "double ratchet"** como el protocolo Signal. Cada mensaje usa
  una clave efímera nueva (secreto hacia adelante *por mensaje*), pero no
  hay recuperación automática de seguridad tras el compromiso de una clave
  a mitad de una conversación prolongada, ni las garantías de
  deniabilidad de Signal.
- El servidor de referencia no implementa autenticación de API
  (cualquiera puede registrar una identidad o consultar el directorio de
  claves públicas). En un despliegue real habría que añadir control de
  acceso, límite de tasa (rate limiting) y TLS terminado correctamente
  (por ejemplo, detrás de un proxy inverso con HTTPS).
- No hay gestión de múltiples dispositivos por identidad, ni revocación de
  claves, ni recuperación de cuenta si se pierde la contraseña (esto es
  una decisión de diseño consciente: sin ellas es más simple, pero también
  significa que **perder la contraseña o el fichero de identidad implica
  perder el acceso a los mensajes futuros irrecuperablemente**, ya que
  nadie —ni el propio proyecto— puede recuperar una clave privada
  perdida).
- No se ha realizado ninguna auditoría de seguridad externa.

## ⚠️ Antes de usar SICN con información sensible

No lo hagas todavía. Esta es una implementación educativa/funcional de
referencia, útil para aprender el diseño de un sistema de mensajería
cifrada de extremo a extremo y como base de futuras mejoras, pero no ha
pasado por un proceso de auditoría de seguridad independiente ni por el
escrutinio que requiere software criptográfico en producción.
