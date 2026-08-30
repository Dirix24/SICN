# SICN Client

Cliente principal utilizado por el usuario: actualmente una interfaz de
línea de comandos (`cli.py`).

Comandos disponibles: `init`, `whoami`, `register`, `add-contact`, `send`,
`inbox`. Ver la [guía de uso rápido en el README principal](../../README.md#️-uso-rápido)
para ejemplos completos.

Un cliente de escritorio con interfaz gráfica y un cliente web están
previstos pero no implementados todavía (ver "Previsto para el futuro" en
el README principal). Deberían reutilizar `src/crypto/` y `src/core/`
directamente, igual que hace este CLI, en vez de reimplementar la lógica
criptográfica.
