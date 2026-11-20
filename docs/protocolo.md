# Protocolo SICN (v1)

Este documento describe el formato de mensaje y el flujo implementados en
`src/core/envelope.py`, `src/crypto/` y `src/server/`.

## Identidad de usuarios

Cada identidad consta de:

- Un par de claves **X25519** (curva elíptica para acuerdo de claves,
  ECDH), usado para el cifrado.
- Un par de claves **Ed25519** (curva elíptica para firmas), usado para la
  autenticidad.
- Una **huella digital** (`fingerprint`): `SHA-256(clave_pública_Ed25519 ||
  clave_pública_X25519)`, en hexadecimal. Es el identificador único de la
  identidad, tanto para enrutar mensajes como para que dos personas la
  comparen manualmente (formateada en grupos de 4 caracteres) y detecten
  un ataque de intermediario (MITM).

Las claves privadas se generan y permanecen siempre en el dispositivo del
usuario. En disco se guardan cifradas (ver "Almacenamiento de claves").

## Formato de mensaje (envelope)

```json
{
  "version": 1,
  "sender_fp": "<huella digital del remitente>",
  "recipient_fp": "<huella digital del destinatario>",
  "ephemeral_public": "<clave pública X25519 efímera, base64>",
  "nonce": "<nonce AES-GCM, base64>",
  "ciphertext": "<contenido cifrado + tag de autenticación, base64>",
  "timestamp": "<ISO 8601 UTC>",
  "filename": "<nombre de archivo o null si es texto>",
  "signature": "<firma Ed25519 sobre todo lo anterior, base64>"
}
```

## Cifrado (sellado del mensaje)

1. El remitente genera un par de claves X25519 **efímero** (de un solo
   uso, distinto para cada mensaje).
2. Calcula el secreto compartido `ECDH(efímera_privada, destinatario_pública)`.
3. Deriva una clave AES-256 de ese secreto con **HKDF-SHA256**.
4. Cifra el contenido con **AES-256-GCM**, usando `sender_fp -> recipient_fp`
   como datos autenticados adicionales (AAD), y un nonce aleatorio de 96 bits.
5. Firma con **Ed25519** (clave estática de identidad del remitente) el
   conjunto de todos los campos del sobre excepto la propia firma.

## Descifrado (apertura del mensaje)

1. El destinatario comprueba que `recipient_fp` coincide con su propia
   huella digital y que `sender_fp` coincide con la del remitente esperado
   (el contacto que tiene guardado).
2. Verifica la firma Ed25519 con la clave pública del remitente. Si no es
   válida, el mensaje se rechaza (pudo ser alterado o no proviene de quien
   dice).
3. Calcula `ECDH(destinatario_privada, efímera_pública)` — el mismo
   secreto compartido que calculó el remitente — y deriva la misma clave
   AES-256 con HKDF.
4. Descifra con AES-256-GCM. Si el contenido fue alterado, la
   autenticación de GCM falla y se rechaza.

## Autenticación e intercambio de claves

- El **intercambio de claves** es un ECDH X25519 efímero-estático por
  mensaje (no hay sesión persistente ni "handshake" previo).
- La **autenticación** del remitente se hace con una firma Ed25519 sobre
  todo el sobre, no con MAC compartido: cualquiera que conozca la clave
  pública del remitente puede verificarla, sin necesitad de contactar al
  servidor.

## Archivos adjuntos

Se tratan igual que el texto: se cifran como bytes, y el campo `filename`
del sobre (no cifrado) indica el nombre original para que el cliente
receptor pueda guardarlo. El contenido del archivo sí está cifrado; solo el
nombre queda visible al servidor.

## Gestión de dispositivos, revocación y recuperación de cuenta

No implementadas en esta versión. Cada identidad vive en un único
dispositivo/directorio de datos. Quedan como trabajo futuro (ver README).

## Versionado del protocolo

El campo `version` en el sobre permite introducir cambios incompatibles en
el futuro sin romper la interoperabilidad con mensajes antiguos.

## Autenticación del relay y entrega

`POST /challenge` acepta `fingerprint`, `operation` y `context`. El contexto es
SHA-256 hexadecimal del JSON canónico del cuerpo sin `proof`. Se ordenan las
claves, se usan separadores compactos y escapes Unicode ASCII. Para registro
se incluyen las dos claves y el nombre, para lectura el cursor `after` y
para confirmación el `id`. Se firma el prefijo ASCII `SICN-RELAY-AUTH-v1`,
un byte nulo y el JSON canónico del desafío completo. El desafío incluye
nonce aleatorio, huella, operación, contexto, audiencia del relay y caducidad.
El cliente envía `proof: {"nonce": "...", "signature": "..."}` con firma
Ed25519 Base64. La ventana es de 60 segundos y consumir la prueba y ejecutar
la operación son parte de la misma transacción SQLite.

La lectura autenticada usa `POST /messages/{fingerprint}`. Cada página
devuelve hasta diez entradas con `id` y `envelope`, y un cursor
`next_after` cuando procede. Descargar no elimina nada. El cliente guarda
el sobre cifrado, comprueba la firma y descifra. Confirma usando
`POST /messages/{fingerprint}/ack`; el relay conserva un registro de ACK
hasta que vence la retención. Reenviar exactamente el mismo sobre dentro
de ese plazo devuelve el ID previo. La entrega es al menos una vez dentro
del plazo de retención.

El formato firmado del sobre v1 se conserva. La autenticación del relay
usa un dominio separado. Los nombres de adjuntos admiten ASCII con letras,
números, espacios internos, punto, guion y guion bajo. Se rechazan nombres
reservados, separadores de ruta y terminaciones en punto o espacio.
