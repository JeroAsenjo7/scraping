"""
Host de prueba (§6.3.3): juega el rol del gateway del arnes.

Levanta el servidor MCP de la tool en proceso, le manda cabeceras
igual que lo haria el gateway real, y la invoca por MCP. Permite
probar cada modo de invocacion: con politica completa, sin politica,
con politica vacia, con identidad y tenant presentes o ausentes.
"""
import contextlib
import json
import threading

import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

import server


class HostDePrueba:
    """
    Cliente MCP que invoca la tool como lo haria el gateway.

    Se usa como context manager asincronico:
        async with HostDePrueba(puerto) as host:
            resultado = await host.invocar(url, politica=...)
    """

    def __init__(self, puerto: int, identidad: str | None = None,
                 tenant: str | None = None):
        self.url_servidor = f"http://127.0.0.1:{puerto}/mcp"
        self.identidad = identidad
        self.tenant = tenant
        self._salir = None
        self.session = None

    def _cabeceras(self, politica) -> dict:
        """Arma las cabeceras igual que el gateway del arnes."""
        cabeceras = {}
        if politica is not None:
            cabeceras["X-LeIA-Egress-Policy"] = (
                politica if isinstance(politica, str) else json.dumps(politica)
            )
        if self.identidad is not None:
            cabeceras["Authorization"] = f"Bearer {self.identidad}"
        if self.tenant is not None:
            cabeceras["X-LeIA-Tenant"] = self.tenant
        return cabeceras

    @contextlib.asynccontextmanager
    async def _sesion(self, politica):
        cabeceras = self._cabeceras(politica)
        async with streamablehttp_client(self.url_servidor, headers=cabeceras) as (r, w, _):
            async with ClientSession(r, w) as session:
                await session.initialize()
                yield session

    async def listar_tools(self, politica=None) -> list[str]:
        async with self._sesion(politica) as session:
            resultado = await session.list_tools()
            return [t.name for t in resultado.tools]

    async def invocar(self, url: str, politica=None) -> str:
        """
        Invoca obtener_contenido_web por MCP. 'politica' puede ser un dict
        (se serializa a JSON), un string crudo, o None para no mandar la
        cabecera en absoluto.
        """
        async with self._sesion(politica) as session:
            resultado = await session.call_tool(
                "obtener_contenido_web", arguments={"url": url}
            )
            return resultado.content[0].text


@contextlib.contextmanager
def servidor_mcp_en_proceso(resolver=None, crear_transporte=None):
    """
    Levanta el servidor MCP de la tool en un hilo, en un puerto libre.

    Si se pasan resolver o crear_transporte, reemplaza las dependencias
    activas del servidor mientras dura el contexto, y las restaura al salir.
    """
    resolver_previo = server.RESOLVER_ACTIVO
    transporte_previo = server.TRANSPORTE_ACTIVO
    if resolver is not None:
        server.RESOLVER_ACTIVO = resolver
    if crear_transporte is not None:
        server.TRANSPORTE_ACTIVO = crear_transporte

    app = server.crear_servidor_mcp().streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    servidor = uvicorn.Server(config)

    hilo = threading.Thread(target=servidor.run, daemon=True)
    hilo.start()

    # Esperamos a que uvicorn informe el puerto asignado
    import time
    for _ in range(100):
        if servidor.started and servidor.servers:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("el servidor MCP no arranco a tiempo")

    puerto = servidor.servers[0].sockets[0].getsockname()[1]

    try:
        yield puerto
    finally:
        servidor.should_exit = True
        hilo.join(timeout=5)
        server.RESOLVER_ACTIVO = resolver_previo
        server.TRANSPORTE_ACTIVO = transporte_previo