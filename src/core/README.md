# SICN Core

Lógica común utilizada por los demás componentes de SICN.

- `envelope.py` — Formato de mensaje ("sobre") y funciones `seal_message`
  / `open_message`: cifrado, firma, verificación y descifrado de extremo a
  extremo. Ver [`docs/protocolo.md`](../../docs/protocolo.md) para el
  formato exacto.
- `contacts.py` — Libreta de contactos local (claves públicas conocidas y
  verificadas por el usuario).

Este módulo no depende de la capa de transporte (HTTP): el mismo código
sirve tanto para el cliente CLI actual como para un futuro cliente gráfico
o extensión de navegador.
