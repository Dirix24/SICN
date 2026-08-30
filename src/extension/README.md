# SICN Extension

Extensión de navegador para usar SICN sin instalar un cliente aparte.

**Estado: no implementada todavía.** Es una de las líneas de trabajo
futuras (ver "Previsto para el futuro" en el [README principal](../../README.md)).

Cuando se implemente, debería reutilizar la misma lógica de
`src/crypto/` y `src/core/` (posiblemente vía WebAssembly o una API local)
en vez de reimplementar la criptografía en JavaScript desde cero, para no
duplicar superficie de ataque.
