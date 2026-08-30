# messages/

Carpeta reservada para ejemplos de mensajes/sobres cifrados de muestra
usados en la documentación (no contiene mensajes reales de ningún
usuario).

Los mensajes reales de un usuario nunca se guardan en el repositorio: el
cliente los cifra, los envía al servidor configurado, y los descifra
localmente en su propio directorio de datos (`SICN_DATA_DIR`), que está
excluido del control de versiones.
