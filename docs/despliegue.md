# Despliegue y migración

Instalación de desarrollo en Python 3.13.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m uvicorn src.server.app:app --host 127.0.0.1 --port 8000
```

Para acceso remoto, termina HTTPS en un proxy configurado por el operador.
Mantén Uvicorn en loopback, acepta cabeceras reenviadas únicamente del proxy
y configura el proxy para reemplazar los encabezados reenviados del cliente.
El esquema reenviado debe ser HTTPS. Aplica límites de tráfico adicionales
en el proxy. El relay responde a `/health` y `/ready`.

`SICN_DB` selecciona el SQLite. `SICN_RETENTION_SECONDS` vale 30 días por
defecto y se aplica al procesar buzones. Las cuotas son de 100 sobres por
buzón, 2000 pendientes en total y 10 000 registros de deduplicación. Un
buzón lleno devuelve 429. Protege con permisos del sistema el directorio
de la base de datos, incluidos los archivos WAL que crea SQLite.

Antes de actualizar, detén el relay anterior y crea un backup fuera del
checkout con `sqlite3 sicn_server.db ".backup /ruta/respaldo.db"`. Verifica
la copia con `sqlite3 /ruta/respaldo.db "PRAGMA integrity_check;"`. Para
restaurar, usa una copia en una ruta nueva y apunta `SICN_DB` a ella.

Al arrancar, SICN añade tablas en una transacción y conserva filas y IDs
existentes. La primera operación de buzón aplica la retención también a
las filas antiguas. Una entrada histórica del directorio cuyas claves
no coincidan con su huella se rechaza. El operador debe revisar esas filas
contra una copia fiable antes de efectuar reparaciones. Actualiza relay y
CLI juntos. Los clientes anteriores no pueden consultar el buzón actualizado.

El almacenamiento seguro del cliente usa funciones POSIX verificadas en
Linux. Los sobres permanecen cifrados en `inbox/`. Los adjuntos verificados
se guardan localmente en claro, con permisos restrictivos. Conserva una
copia del archivo de identidad cifrada y su contraseña por separado.
