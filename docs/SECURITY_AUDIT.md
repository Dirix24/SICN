# Revisión de seguridad de SICN 0.2.0

Revisión interna con asistencia de IA. La auditoría criptográfica externa
queda pendiente.

| Severidad | Riesgo en la base | Cambio y prueba |
| --- | --- | --- |
| P0 | La consulta del buzón aceptaba solo una huella y borraba las filas al leerlas. | La lectura y el ACK requieren firmas vinculadas al contexto. Los sobres sobreviven a cortes, reinicios y reintentos antes del ACK. |
| P0 | El registro permitía sobrescribir las claves asociadas a una huella. | Prueba de posesión Ed25519, validación del vínculo con X25519 y filas inmutables. Pruebas de firma incorrecta, sustitución y carreras. |
| P1 | El cliente usaba directamente el nombre de adjunto recibido. | Validación ASCII y publicación local sin sobrescritura, con pruebas de rutas, nombres reservados y symlinks. |
| P1 | El relay no verificaba la firma del sobre ni acotaba las solicitudes. | Validación criptográfica, límites de API, cuotas, expiración y HTTPS fuera de loopback. |
| P2 | Retención sin gestión explícita y una base compartida global al importar. | Apertura en el ciclo de vida de la aplicación, conservación de bases anteriores probada y guía de operación. La limpieza programada queda pendiente. |
| P3 | CLI con recuperación limitada ante errores de red y archivos. | Reintento por nueva consulta y deduplicación de escritura local. Pendientes los comandos de recuperación histórica y una cola de salida persistente. |

La rama base ejecutó 17 pruebas. La revisión ejecutó 29 pruebas y añade cobertura de
autenticación, reintento, reinicio, migración, adjuntos y límites HTTP.
Quedan pendientes rotación de identidad, auditoría externa, vectores
deterministas del protocolo y pruebas de despliegue con un proxy real.

En una instalación limpia de Python 3.13, la compilación de módulos y
`pip-audit` del entorno instalado terminaron correctamente. Starlette emitió
una advertencia de deprecación de su integración de pruebas con httpx.
