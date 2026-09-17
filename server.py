from mcp.server.fastmcp import FastMCP
from urllib.parse import urlparse, urljoin # parsear URLs (direcciones)
import httpx # para hacer pedidos HTTP (GET, POST, etc) a otros servidores
import socket # para resolver nombres de host a IPs (dominio a IP)
import ipaddress # verifica los tipos de IPs (privadas, loopback, link-local, etc)

mcp = FastMCP("mcp-web", stateless_http=True)

MAX_REDIRECCIONES = 5


def resolver_todas_las_ips(host: str) -> list[str]:
    """Resuelve un host a TODAS sus IPs (no solo la primera)."""
    resultados = socket.getaddrinfo(host, None) # devuelve que IPs corresponden al dominio
    # getaddrinfo devuelve tuplas con mucha info; nos interesa el IP,
    # que esta en la posicion [4][0] de cada tupla - expresion
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


def host_es_seguro(host: str) -> bool: 
    """True solo si TODAS las IPs a las que resuelve el host son publicas."""
    ips = resolver_todas_las_ips(host)
    for ip in ips:
        if es_ip_privada_o_interna(ip):
            return False
    return True


def validar_url(url: str) -> str | None:
    """
    Valida esquema y destino de una URL.
    Devuelve None si es valida, o un mensaje de error si no lo es.
    Se usa tanto para la URL inicial como para cada salto de redireccion.
    """
    partes = urlparse(url)

    if partes.scheme not in ("http", "https"):
        return f"esquema no permitido: {partes.scheme}"

    host = partes.hostname
    if host is None:
        return "no se pudo determinar el host de la URL"

    try:
        if not host_es_seguro(host):
            return f"destino no permitido (host interno/privado): {host}"
    except socket.gaierror:
        return f"no se pudo resolver el host: {host}"

    return None


@mcp.tool()
async def obtener_contenido_web(url: str) -> str:
    """
    Trae el contenido de texto de una URL publica.

    Rechaza direcciones que apunten a destinos internos o privados
    de la red (loopback, rangos privados, link-local, etc), incluyendo
    destinos alcanzados a traves de redirecciones: cada salto se valida
    individualmente antes de seguirlo, con un maximo de saltos permitidos.

    ADVERTENCIA: version parcial, todavia sin defensa contra DNS
    rebinding (la IP se valida pero la conexion todavia no queda
    fijada a esa IP validada).
    """
    url_actual = url
    saltos = 0 # contador de redirecciones seguidas

    # follow_redirects=False de forma EXPLICITA: no queremos depender
    # del comportamiento por defecto de la libreria, sea cual sea.
    async with httpx.AsyncClient(follow_redirects=False) as client:
        while True:
            error = validar_url(url_actual) # lammamos a validar_url para ver comprobarla
            if error is not None:
                return f"ERROR: {error}"  

            response = await client.get(url_actual) 

            if response.is_redirect: # calcula el estado True si el codigo de estado es 3xx (redireccion)
                # permitimos 5 redirecciones seguidas, luego cortamos para evitar loops infinitos
                saltos += 1
                if saltos > MAX_REDIRECCIONES:
                    return f"ERROR: demasiadas redirecciones (limite: {MAX_REDIRECCIONES})"
                # si no hay cabecera Location, no podemos seguir la redireccion, devolvemos error
                location = response.headers.get("location")
                if not location:
                    return "ERROR: redireccion sin cabecera Location"

                # urljoin resuelve URLs relativas (ej: Location: /otra-pagina)
                # contra la URL actual, igual que hace un navegador.
                url_actual = urljoin(url_actual, location)
                continue

            return response.text


if __name__ == "__main__":
    mcp.run(transport="streamable-http")