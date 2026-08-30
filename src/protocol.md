# SICN Protocol

La especificación completa del protocolo de comunicación está en
[`docs/protocolo.md`](../docs/protocolo.md), junto con el resto de la
documentación de arquitectura y seguridad.

La implementación de referencia del protocolo vive en
[`src/core/envelope.py`](core/envelope.py) (formato del sobre y
sellado/apertura de mensajes) y [`src/crypto/`](crypto/) (primitivas
criptográficas subyacentes).
