# Contribuir a SICN

SICN está en desarrollo activo (versión 0.2.0).

Las contribuciones deben priorizar seguridad, privacidad, simplicidad,
pruebas y documentación.

## Antes de enviar un cambio

1. **No añadas criptografía propia.** Usa siempre primitivas de la
   librería `cryptography` (u otra biblioteca estándar y mantenida),
   nunca implementaciones caseras de algoritmos criptográficos.
2. **Añade tests.** Cualquier cambio en `src/crypto/` o `src/core/`
   necesita tests que cubran el caso normal y, si aplica, casos de
   manipulación/ataque (ver `tests/test_envelope.py` como referencia).
3. Ejecuta la suite completa antes de proponer el cambio:
   ```bash
   pip install -r requirements-dev.txt
   pytest
   ```
4. Si tocas el formato del sobre (`Envelope`) o el protocolo, actualiza
   `docs/protocolo.md` en el mismo cambio.
5. Si el cambio afecta a supuestos de seguridad (qué ve el servidor, qué
   garantías da el cifrado, etc.), actualiza también `docs/seguridad.md`.

## Qué es bienvenido ahora mismo

- Cliente con interfaz gráfica de escritorio o cliente web.
- Extensión de navegador.
- Gestión de múltiples dispositivos y revocación de claves.
- Mejoras al servidor: autenticación de API, límite de tasa, despliegue
  con TLS.
- Más tests, especialmente de casos límite y de seguridad.

## Qué evitar

- Añadir dependencias criptográficas no auditadas o poco mantenidas.
- Introducir opciones que debiliten el cifrado por defecto (por ejemplo,
  "modo sin cifrar" para depuración) sin dejarlo explícitamente marcado
  como inseguro y fuera de las rutas por defecto.
