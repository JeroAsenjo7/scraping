import asyncio
import contextlib
import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import httpx

import json

from server import (
    obtener_contenido,
    es_ip_privada_o_interna,
    TransporteIPFija,
    PoliticaEgreso,
    PoliticaInvalida,
)

def politica(hosts, **extra):
    """Arma una politica de prueba a partir de la lista de hosts permitidos."""
    datos = {"hosts": hosts, "esquemas": ["http", "https"]}
    datos.update(extra)
    return PoliticaEgreso.desde_json(json.dumps(datos))

# IPs publicas SIMULADAS: la validacion las ve como publicas, pero la
# red simulada las dirige a servidores locales. Nunca se sale a internet.
IP_PUBLICA_SIMULADA = "93.184.216.34"


# ---------------------------------------------------------------------
# Infraestructura de prueba
# ---------------------------------------------------------------------
# crea handlers HTTP confugrables, segun parametros recibidos
def crear_handler(registro: list, cuerpo: str = "", redirigir_a: str | None = None):
    """Crea un handler HTTP que anota cada pedido recibido en 'registro'."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            registro.append(self.path)
            if redirigir_a is not None:
                self.send_response(302)
                self.send_header("Location", redirigir_a)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            datos = cuerpo.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(datos)))
            self.end_headers()
            self.wfile.write(datos)

        def log_message(self, *args):
            pass  # silencio en los tests

    return Handler


@contextlib.contextmanager
def servidor_local(handler):
    """Levanta un servidor en 127.0.0.1 en un puerto libre y devuelve el puerto."""
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown()
        servidor.server_close()


def crear_resolver(tabla: dict):
    """
    Resolver DNS falso. 'tabla' mapea host -> lista de IPs, o host -> funcion
    que recibe el numero de consulta (1, 2, ...) y devuelve la lista de IPs.
    Las IPs literales se devuelven tal cual, igual que el resolver real.
    """
    llamadas = []

    def resolver(host: str) -> list[str]:
        llamadas.append(host)
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        if host not in tabla:
            raise socket.gaierror(f"host desconocido: {host}")
        respuesta = tabla[host]
        if callable(respuesta):
            return respuesta(llamadas.count(host))
        return respuesta

    resolver.llamadas = llamadas
    return resolver


class RedSimulada:
    """
    Fabrica de transporte para los tests: registra que IP fijo la tool
    y dirige toda conexion a 127.0.0.1 (nunca sale a internet).
    """

    def __init__(self):
        self.ips_fijadas = []

    def crear_transporte(self, ip: str):
        self.ips_fijadas.append(ip)
        return TransporteIPFija("127.0.0.1")


def ejecutar(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------
# Caso feliz
# ---------------------------------------------------------------------

def test_caso_feliz_sitio_publico():
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="CONTENIDO PUBLICO")) as puerto:
        resolver = crear_resolver({"sitio-publico.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://sitio-publico.test:{puerto}/",
            politica(["sitio-publico.test"]), resolver, red.crear_transporte))

    assert "CONTENIDO PUBLICO" in resultado
    assert red.ips_fijadas == [IP_PUBLICA_SIMULADA]


# ---------------------------------------------------------------------
# SSRF (§7.1)
# ---------------------------------------------------------------------

def test_ssrf_ip_literal_loopback():
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="PANEL INTERNO")) as puerto:
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://127.0.0.1:{puerto}/",
            politica(["127.0.0.1"]), crear_resolver({}), red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert pedidos == []          # el servidor interno nunca fue contactado
    assert red.ips_fijadas == []  # nunca se llego a conectar


def test_ssrf_metadata_cloud():
    red = RedSimulada()
    resultado = ejecutar(obtener_contenido(
        "http://169.254.169.254/latest/meta-data/",
        politica(["169.254.169.254"]), crear_resolver({}), red.crear_transporte))
    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


def test_ssrf_dominio_que_resuelve_a_ip_privada():
    resolver = crear_resolver({"interno.test": ["10.0.0.5"]})
    red = RedSimulada()
    resultado = ejecutar(obtener_contenido(
        "http://interno.test/", politica(["interno.test"]),
        resolver, red.crear_transporte))
    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


def test_dns_con_registros_mixtos_publico_e_interno():
    # §7.3: un dominio que devuelve una IP publica Y una interna a la vez
    resolver = crear_resolver({"mixto.test": [IP_PUBLICA_SIMULADA, "127.0.0.1"]})
    red = RedSimulada()
    resultado = ejecutar(obtener_contenido(
        "http://mixto.test/", politica(["mixto.test"]),
        resolver, red.crear_transporte))
    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


# ---------------------------------------------------------------------
# Redirecciones (§7.2)
# ---------------------------------------------------------------------

def test_redireccion_hacia_interno_es_bloqueada():
    pedidos_interno = []
    pedidos_redirector = []
    with servidor_local(crear_handler(pedidos_interno, cuerpo="PANEL INTERNO")) as p_interno:
        destino = f"http://127.0.0.1:{p_interno}/"
        with servidor_local(crear_handler(pedidos_redirector, redirigir_a=destino)) as p_redir:
            resolver = crear_resolver({"sitio-publico.test": [IP_PUBLICA_SIMULADA]})
            red = RedSimulada()
            resultado = ejecutar(obtener_contenido(
                f"http://sitio-publico.test:{p_redir}/",
                politica(["sitio-publico.test"]), resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert pedidos_redirector == ["/"]       # el primer salto si ocurrio
    assert pedidos_interno == []             # el interno NUNCA fue contactado
    assert red.ips_fijadas == [IP_PUBLICA_SIMULADA]  # solo se conecto al primer salto


def test_redireccion_hacia_dominio_que_resuelve_a_privada():
    pedidos_redirector = []
    with servidor_local(crear_handler(pedidos_redirector,
                                      redirigir_a="http://interno.test/")) as p_redir:
        resolver = crear_resolver({
            "sitio-publico.test": [IP_PUBLICA_SIMULADA],
            "interno.test": ["192.168.1.10"],
        })
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://sitio-publico.test:{p_redir}/",
            politica(["sitio-publico.test", "interno.test"]),
            resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == [IP_PUBLICA_SIMULADA]


def test_redireccion_legitima_se_sigue():
    pedidos_publico = []
    with servidor_local(crear_handler(pedidos_publico, cuerpo="DESTINO FINAL")) as p_pub:
        destino = f"http://otro-publico.test:{p_pub}/"
        with servidor_local(crear_handler([], redirigir_a=destino)) as p_redir:
            resolver = crear_resolver({
                "sitio-publico.test": [IP_PUBLICA_SIMULADA],
                "otro-publico.test": [IP_PUBLICA_SIMULADA],
            })
            red = RedSimulada()
            resultado = ejecutar(obtener_contenido(
                f"http://sitio-publico.test:{p_redir}/",
                politica(["sitio-publico.test", "otro-publico.test"]),
                resolver, red.crear_transporte))

    assert "DESTINO FINAL" in resultado
    assert len(red.ips_fijadas) == 2  # un salto validado y fijado por cada host


def test_limite_de_redirecciones():
    # El servidor se redirige a si mismo indefinidamente
    with servidor_local(crear_handler([], redirigir_a="/")) as p_redir:
        resolver = crear_resolver({"bucle.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://bucle.test:{p_redir}/",
            politica(["bucle.test"]), resolver, red.crear_transporte))

    assert "demasiadas redirecciones" in resultado


# ---------------------------------------------------------------------
# DNS rebinding (§7.3): primero cae la version ingenua, despues resiste
# la propuesta
# ---------------------------------------------------------------------

def dns_de_rebinding(numero_consulta: int) -> list[str]:
    """1ra consulta: IP publica. Consultas siguientes: loopback."""
    return [IP_PUBLICA_SIMULADA] if numero_consulta == 1 else ["127.0.0.1"]


async def obtener_ingenuo(url, resolver, crear_transporte):
    """
    Implementacion INGENUA, solo para el test: valida con una consulta DNS
    y conecta con OTRA consulta (lo que hace httpx si no se fija la IP).
    """
    host = urlparse(url).hostname
    ips = resolver(host)                              # consulta 1: validacion
    if any(es_ip_privada_o_interna(ip) for ip in ips):
        return "ERROR"
    ip_conexion = resolver(host)[0]                   # consulta 2: conexion
    async with httpx.AsyncClient(transport=crear_transporte(ip_conexion)) as c:
        respuesta = await c.get(url)
        return respuesta.text


def test_rebinding_implementacion_ingenua_cae():
    with servidor_local(crear_handler([], cuerpo="CONTENIDO")) as puerto:
        resolver = crear_resolver({"atacante.test": dns_de_rebinding})
        red = RedSimulada()
        ejecutar(obtener_ingenuo(
            f"http://atacante.test:{puerto}/", resolver, red.crear_transporte))

    assert len(resolver.llamadas) == 2       # se pregunto dos veces al DNS
    assert red.ips_fijadas == ["127.0.0.1"]  # termino conectando al interno


def test_rebinding_propuesta_resiste():
    with servidor_local(crear_handler([], cuerpo="CONTENIDO")) as puerto:
        resolver = crear_resolver({"atacante.test": dns_de_rebinding})
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://atacante.test:{puerto}/",
            politica(["atacante.test"]), resolver, red.crear_transporte))

    assert resolver.llamadas == ["atacante.test"]    # UNA sola consulta DNS
    assert red.ips_fijadas == [IP_PUBLICA_SIMULADA]  # conecto a la IP validada
    assert "CONTENIDO" in resultado


# ---------------------------------------------------------------------
# Politica de egreso (ADR-020 seccion 2)
# ---------------------------------------------------------------------

def test_politica_ausente_falla_cerrada():
    import pytest
    with pytest.raises(PoliticaInvalida) as exc:
        PoliticaEgreso.desde_json(None)
    assert "no declarada" in str(exc.value)


def test_politica_vacia_se_distingue_de_ausente():
    import pytest
    with pytest.raises(PoliticaInvalida) as exc:
        PoliticaEgreso.desde_json('{"hosts": []}')
    assert "sin destinos permitidos" in str(exc.value)


def test_politica_mal_formada():
    import pytest
    with pytest.raises(PoliticaInvalida) as exc:
        PoliticaEgreso.desde_json("esto no es json")
    assert "mal formada" in str(exc.value)


def test_host_fuera_de_allowlist_se_bloquea():
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="NO DEBERIA LLEGAR")) as puerto:
        resolver = crear_resolver({"otro-sitio.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://otro-sitio.test:{puerto}/",
            politica(["sitio-permitido.test"]), resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert pedidos == []
    assert red.ips_fijadas == []


def test_subdominio_bloqueado_por_defecto():
    resolver = crear_resolver({"sub.sitio.test": [IP_PUBLICA_SIMULADA]})
    red = RedSimulada()
    resultado = ejecutar(obtener_contenido(
        "http://sub.sitio.test/", politica(["sitio.test"]),
        resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


def test_subdominio_permitido_si_la_politica_lo_habilita():
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="CONTENIDO SUB")) as puerto:
        resolver = crear_resolver({"sub.sitio.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://sub.sitio.test:{puerto}/",
            politica(["sitio.test"], incluir_subdominios=True),
            resolver, red.crear_transporte))

    assert "CONTENIDO SUB" in resultado


def test_dominio_que_termina_parecido_no_pasa_como_subdominio():
    # "malsitio.test" NO es subdominio de "sitio.test"
    resolver = crear_resolver({"malsitio.test": [IP_PUBLICA_SIMULADA]})
    red = RedSimulada()
    resultado = ejecutar(obtener_contenido(
        "http://malsitio.test/", politica(["sitio.test"], incluir_subdominios=True),
        resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


def test_credenciales_embebidas_en_url_se_rechazan():
    resolver = crear_resolver({"sitio.test": [IP_PUBLICA_SIMULADA]})
    red = RedSimulada()
    resultado = ejecutar(obtener_contenido(
        "http://usuario:clave@sitio.test/", politica(["sitio.test"]),
        resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


def test_esquema_fuera_de_politica_se_rechaza():
    resolver = crear_resolver({"sitio.test": [IP_PUBLICA_SIMULADA]})
    red = RedSimulada()
    # politica que solo admite https, pedido por http
    pol = PoliticaEgreso.desde_json(json.dumps({
        "hosts": ["sitio.test"], "esquemas": ["https"]}))
    resultado = ejecutar(obtener_contenido(
        "http://sitio.test/", pol, resolver, red.crear_transporte))

    assert resultado.startswith("ERROR")
    assert red.ips_fijadas == []


def test_limite_de_caracteres_devueltos():
    contenido_largo = "A" * 5000
    with servidor_local(crear_handler([], cuerpo=contenido_largo)) as puerto:
        resolver = crear_resolver({"sitio.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        resultado = ejecutar(obtener_contenido(
            f"http://sitio.test:{puerto}/",
            politica(["sitio.test"], limites={"max_chars_devueltos": 100}),
            resolver, red.crear_transporte))

    assert len(resultado) == 100