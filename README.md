# 🔐 SISC

> **Sistema de Información Segura y Cifrada**

## 🌐 Visión

SISC es un sistema de comunicación cifrada inspirado en los servicios modernos de correo electrónico.

El objetivo es que los usuarios puedan enviar y recibir mensajes y archivos cifrados.

La arquitectura busca que el contenido sensible se cifre en el dispositivo del usuario y que el servidor almacene y transporte datos cifrados.

## 🔒 Funcionamiento

```text
Usuario A
   ↓
Cifrado local
   ↓
Servidor SISC
   ↓
Datos cifrados
   ↓
Usuario B
   ↓
Descifrado local
   ↓
Mensaje original
```

## 🚀 Características previstas

- Mensajería cifrada
- Archivos cifrados
- Gestión de claves
- Identidad de usuarios
- Firmas digitales
- Verificación de identidad
- Cliente de escritorio
- Cliente web
- Extensión para navegador
- Servidor
- API
- Notificaciones
- Contactos
- Búsqueda
- Protección de sesiones

## 🧩 Componentes

```text
SISC/
├── client/       Cliente
├── server/       Servidor
├── extension/    Extensión del navegador
├── crypto/       Criptografía
├── core/         Código común
├── protocol/     Protocolo de comunicación
├── keys/         Gestión local de claves
├── messages/     Mensajes
├── files/        Archivos
├── tests/        Pruebas
├── docs/         Documentación
└── examples/     Ejemplos
```

## ⚠️ Seguridad

SISC no debe inventar algoritmos criptográficos propios para producción.

El proyecto utilizará primitivas y bibliotecas criptográficas estándar y mantenidas. Antes de utilizar SISC para información sensible será necesario realizar pruebas y auditorías de seguridad.

## 📌 Estado

Versión actual: **0.1.0**

Proyecto en desarrollo.

> 🔐 Privacidad primero. Seguridad siempre.
