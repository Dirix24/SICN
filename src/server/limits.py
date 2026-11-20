from fastapi import HTTPException
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

MAX_BODY_BYTES = 360_000


class RequestBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        length = Headers(scope=scope).get("content-length")
        if length is not None and (not length.isascii() or not length.isdecimal() or len(length) > 12):
            return await JSONResponse({"detail": "Content-Length inválido"}, status_code=400)(scope, receive, send)
        if length is not None and int(length) > MAX_BODY_BYTES:
            return await JSONResponse({"detail": "Cuerpo de solicitud demasiado grande"}, status_code=413)(
                scope, receive, send,
            )

        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > MAX_BODY_BYTES:
                    raise HTTPException(413, "Cuerpo de solicitud demasiado grande")
            return message

        return await self.app(scope, limited_receive, send)
