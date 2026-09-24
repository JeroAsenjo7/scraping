from collections.abc import Callable
from mcp.server.fastmcp import FastMCP
from urllib.parse import urlparse, urljoin
import httpx
import socket
import ipaddress
#politicas de cabecera 
from dataclasses import dataclass, field
import json 


mcp = FastMCP("mcp-web", stateless_http=True)

MAX_REDIRECCIONES = 5

# Tipos de las dependencias inyectables
# cualquier funcion que recibe un host (devuelve IPs)
Resolver = Callable[[str], list[str]] 
# cualquier funcion que recibe una IP y devuelve un transporte httpx
FabricaTransporte = Callable[[str], httpx.AsyncBaseTransport] 
# no cambian en tiempo de ejecución

def resolver_todas_las_ips(host: str) -> list[str]:
    """Resolvedor REAL: resuelve un host a TODAS sus IPs."""
    resultados = socket.getaddrinfo(host, None)
    ips = {r[4][0] for r in resultados}
    return list(ips)


def es_ip_privada_o_interna(ip_texto: str) -> bool:
    """True si la IP es privada, loopback, link-local, reservada o multicast."""
    ip = ipaddress.ip_address(ip_texto)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )

# recibe el resolvedor (resolver)
def resolver_ip_segura(host: str, resolver: Resolver) -> tuple[str | None, str | None]:
    """
    Resuelve un host UNA SOLA VEZ (con el resolver recibido) y devuelve
    una IP publica valida, o un mensaje de error.
    """
    try:
        ips = resolver(host)
    except socket.gaierror:
        return None, f"no se pudo resolver el host: {host}"

    if not ips:
        return None, f"el host no resolvio a ninguna IP: {host}"

    for ip in ips:
        if es_ip_privada_o_interna(ip):
            return None, f"destino no permitido (host interno/privado): {host}"

    return ips[0], None


def validar_esquema(url: str) -> str | None:
    """Valida esquema y presencia de host."""
    partes = urlparse(url)
    if partes.scheme not in ("http", "https"):
        return f"esquema no permitido: {partes.scheme}"
    if partes.hostname is None:
        return "no se pudo determinar el host de la URL"
    return None


class TransporteIPFija(httpx.AsyncHTTPTransport):
    """
    Fuerza la conexion a una IP ya validada (defensa contra rebinding).
    httpx ya armo la cabecera Host con el dominio original, asi que no
    se toca. Para HTTPS se indica el dominio original como SNI, para que
    la negociacion TLS y la verificacion del certificado usen el nombre
    y no la IP.
    """

    def __init__(self, ip_destino: str, **kwargs):
        super().__init__(**kwargs)
        self.ip_destino = ip_destino

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host_original = request.url.host
        request.extensions = {**request.extensions, "sni_hostname": host_original}
        request.url = request.url.copy_with(host=self.ip_destino)
        return await super().handle_async_request(request)


async def obtener_contenido(
    url: str,
    resolver: Resolver = resolver_todas_las_ips,
    crear_transporte: FabricaTransporte = TransporteIPFija,
) -> str:
    """
    Logica central de la tool, con sus dependencias inyectables.
    En produccion se usan los valores por defecto; en las pruebas se
    inyectan un resolver falso y una fabrica de transporte controlada.
    """
    url_actual = url
    saltos = 0

    while True:
        error = validar_esquema(url_actual)
        if error is not None:
            return f"ERROR: {error}"

        host = urlparse(url_actual).hostname
        ip_validada, error = resolver_ip_segura(host, resolver)
        if error is not None:
            return f"ERROR: {error}"
        # el transporte se construye llamando a crear_transporte
        # con la ip validada
        try:
            async with httpx.AsyncClient(
                transport=crear_transporte(ip_validada), follow_redirects=False
            ) as client:
                response = await client.get(url_actual)
        except httpx.HTTPError:
            return "ERROR: no se pudo obtener el contenido (fallo de red o del sitio)"

        if response.is_redirect:
            saltos += 1
            if saltos > MAX_REDIRECCIONES:
                return f"ERROR: demasiadas redirecciones (limite: {MAX_REDIRECCIONES})"

            location = response.headers.get("location")
            if not location:
                return "ERROR: redireccion sin cabecera Location"

            url_actual = urljoin(url_actual, location)
            continue

        return response.text

# la tool mcp como envoltorio 
@mcp.tool()
async def obtener_contenido_web(url: str) -> str:
    """
    Trae el contenido de texto de una URL publica.

    Rechaza destinos internos o privados de la red, incluidos los
    alcanzados por redirecciones (cada salto se valida antes de seguirlo,
    con un maximo de saltos). Cada host se resuelve una sola vez y la
    conexion queda fijada a esa IP validada, para prevenir DNS rebinding.
    """
    return await obtener_contenido(url)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")