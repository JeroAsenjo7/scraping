from collections.abc import Callable
from mcp.server.fastmcp import FastMCP
from urllib.parse import urlparse, urljoin
import httpx
import socket
import ipaddress
#politicas de cabecera 
from dataclasses import dataclass, field
import json 
from mcp.server.fastmcp import FastMCP, Context


# Valores por defecto de los limites, usados solo si la politica
# declarada no especifica alguno. No hay default para 'hosts':
# sin hosts la tool no opera (falla cerrada).
LIMITES_POR_DEFECTO = {
    "bytes_recibidos": 5_242_880,
    "bytes_descomprimidos": 20_971_520,
    "timeout_peticion_s": 30,
    "timeout_total_s": 60,
    "max_saltos": 5,
    "max_chars_devueltos": 15_000,
}

class PoliticaInvalida(Exception):
    """La politica declarada esta ausente, mal formada o sin destinos."""

@dataclass
class PoliticaEgreso:
    """Politica de salida declarada por quien invoca la tool."""
    hosts: list[str]
    incluir_subdominios: bool = False
    esquemas: list[str] = field(default_factory=lambda: ["https"])
    limites: dict = field(default_factory=lambda: dict(LIMITES_POR_DEFECTO))
    derivadas: dict = field(default_factory=lambda: {"seguir": False,
                                                    "solo_misma_allowlist": True})
    crudo: dict = field(default_factory=dict)

    @classmethod
    def desde_json(cls, texto: str | None) -> "PoliticaEgreso":
        if texto is None or texto.strip() == "":
            raise PoliticaInvalida("politica de salida no declarada")

        try:
            datos = json.loads(texto)
        except json.JSONDecodeError:
            raise PoliticaInvalida("politica de salida mal formada (JSON invalido)")

        if not isinstance(datos, dict):
            raise PoliticaInvalida("politica de salida mal formada (se esperaba un objeto)")

        hosts = datos.get("hosts")
        if not hosts or not isinstance(hosts, list):
            raise PoliticaInvalida("politica sin destinos permitidos")

        limites = dict(LIMITES_POR_DEFECTO)
        limites.update(datos.get("limites") or {})

        return cls(
            hosts=[h.lower() for h in hosts],
            incluir_subdominios=bool(datos.get("incluir_subdominios", False)),
            esquemas=datos.get("esquemas") or ["https"],
            limites=limites,
            derivadas=datos.get("derivadas") or {"seguir": False,
                                                 "solo_misma_allowlist": True},
            crudo=datos,
        )

    def host_permitido(self, host: str) -> bool:
        host = host.lower()
        for permitido in self.hosts:
            if host == permitido:
                return True
            if self.incluir_subdominios and host.endswith("." + permitido):
                return True
        return False

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


def validar_url_contra_politica(url: str, politica: PoliticaEgreso) -> str | None:
    """
    Valida esquema, credenciales embebidas y pertenencia a la allowlist.
    Devuelve None si es valida, o un mensaje de error si no lo es.
    """
    partes = urlparse(url)

    if partes.scheme not in politica.esquemas:
        return f"esquema no permitido por la politica: {partes.scheme}"

    if partes.username is not None or partes.password is not None:
        return "no se permiten credenciales embebidas en la URL"

    host = partes.hostname
    if host is None:
        return "no se pudo determinar el host de la URL"

    if not politica.host_permitido(host):
        return "destino fuera de la lista de hosts permitidos"

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

# Dependencias activas del servidor. En produccion son las reales.
# El host de prueba las reemplaza para correr sin DNS ni red externa.
RESOLVER_ACTIVO: Resolver = resolver_todas_las_ips
TRANSPORTE_ACTIVO: FabricaTransporte = TransporteIPFija


async def obtener_contenido(
    url: str,
    politica: PoliticaEgreso,
    resolver: Resolver = resolver_todas_las_ips,
    crear_transporte: FabricaTransporte = TransporteIPFija,
) -> str:
    """
    Logica central de la tool. La politica es obligatoria: sin ella
    la tool no opera (se valida antes de llamar a esta funcion).
    """
    url_actual = url
    saltos = 0
    max_saltos = politica.limites["max_saltos"]
    timeout_peticion = politica.limites["timeout_peticion_s"]

    while True:
        error = validar_url_contra_politica(url_actual, politica)
        if error is not None:
            return f"ERROR: {error}"

        host = urlparse(url_actual).hostname
        ip_validada, error = resolver_ip_segura(host, resolver)
        if error is not None:
            return f"ERROR: {error}"

        try:
            async with httpx.AsyncClient(
                transport=crear_transporte(ip_validada),
                follow_redirects=False,
                timeout=timeout_peticion,
            ) as client:
                response = await client.get(url_actual)
        except httpx.HTTPError:
            return "ERROR: no se pudo obtener el contenido (fallo de red o del sitio)"

        if response.is_redirect:
            saltos += 1
            if saltos > max_saltos:
                return f"ERROR: demasiadas redirecciones (limite: {max_saltos})"

            location = response.headers.get("location")
            if not location:
                return "ERROR: redireccion sin cabecera Location"

            url_actual = urljoin(url_actual, location)
            continue

        texto = response.text
        max_chars = politica.limites["max_chars_devueltos"]
        if len(texto) > max_chars:
            texto = texto[:max_chars]
        return texto

def leer_cabecera_politica(ctx) -> str | None:
    """Lee X-LeIA-Egress-Policy de la peticion MCP, si esta presente."""
    try:
        request = ctx.request_context.request
        if request is None:
            return None
        return request.headers.get("x-leia-egress-policy")
    except (AttributeError, ValueError):
        return None

# reemplace el decorador @mcp.tool por esto:

async def obtener_contenido_web(url: str, ctx: Context) -> str:
    """
    Trae el contenido de texto de una URL publica.

    Requiere que quien la invoque declare una politica de salida en la
    cabecera X-LeIA-Egress-Policy (JSON inline). Sin politica, la tool
    no opera.

    Rechaza destinos fuera de la allowlist declarada, y destinos internos
    o privados de la red, incluidos los alcanzados por redirecciones.
    Cada host se resuelve una sola vez y la conexion queda fijada a esa
    IP validada, para prevenir DNS rebinding.

    No garantiza ritmo maximo hacia un mismo destino ni limite de pedidos
    simultaneos: son garantias del gateway, no de esta tool.
    """
    cabecera = leer_cabecera_politica(ctx)

    try:
        politica = PoliticaEgreso.desde_json(cabecera)
    except PoliticaInvalida as e:
        return f"ERROR: {e}"

    return await obtener_contenido(url, politica, RESOLVER_ACTIVO, TRANSPORTE_ACTIVO)


def crear_servidor_mcp() -> FastMCP:
    """
    Fabrica una instancia nueva del servidor MCP con la tool registrada.

    Cada instancia solo puede levantarse una vez (limitacion del
    StreamableHTTPSessionManager del SDK), por eso el host de prueba
    necesita una instancia propia por cada servidor que levanta.
    """
    instancia = FastMCP("mcp-web", stateless_http=True)
    instancia.tool()(obtener_contenido_web)
    return instancia


mcp = crear_servidor_mcp()



if __name__ == "__main__":
    mcp.run(transport="streamable-http")