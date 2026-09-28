"""
Suite de contrato: invoca la tool por MCP, igual que lo haria el gateway.
Verifica la regla de aceptacion de §6.3.4.
"""
import asyncio
import json

import pytest

from host_prueba import HostDePrueba, servidor_mcp_en_proceso
from test_ataques import (
    IP_PUBLICA_SIMULADA,
    RedSimulada,
    crear_handler,
    crear_resolver,
    servidor_local,
)


def ejecutar(coro):
    return asyncio.run(coro)


POLITICA_BASE = {
    "hosts": ["sitio-publico.test"],
    "esquemas": ["http", "https"],
}


def test_mcp_tool_esta_registrada():
    with servidor_mcp_en_proceso() as puerto:
        host = HostDePrueba(puerto)
        tools = ejecutar(host.listar_tools(politica=POLITICA_BASE))
    assert "obtener_contenido_web" in tools


def test_mcp_con_politica_completa():
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="CONTENIDO OK")) as p_web:
        resolver = crear_resolver({"sitio-publico.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        with servidor_mcp_en_proceso(resolver, red.crear_transporte) as p_mcp:
            host = HostDePrueba(p_mcp, identidad="usuario-test", tenant="tenant-test")
            resultado = ejecutar(host.invocar(
                f"http://sitio-publico.test:{p_web}/", politica=POLITICA_BASE))

    assert "CONTENIDO OK" in resultado["contenido"]
    assert resultado["procedencia"]["politica_aplicada"] == POLITICA_BASE
    assert resultado["procedencia"]["sha256"]
    assert red.ips_fijadas == [IP_PUBLICA_SIMULADA]


def test_mcp_sin_politica_falla_cerrada():
    with servidor_mcp_en_proceso() as puerto:
        host = HostDePrueba(puerto)
        error = ejecutar(host.invocar_esperando_error(
            "http://sitio-publico.test/", politica=None))

    assert "egress_bloqueado" in error
    assert "no declarada" in error


def test_mcp_politica_vacia_se_distingue():
    with servidor_mcp_en_proceso() as puerto:
        host = HostDePrueba(puerto)
        error = ejecutar(host.invocar_esperando_error(
            "http://sitio-publico.test/", politica={"hosts": []}))

    assert "sin destinos permitidos" in error


def test_mcp_politica_mal_formada():
    with servidor_mcp_en_proceso() as puerto:
        host = HostDePrueba(puerto)
        error = ejecutar(host.invocar_esperando_error(
            "http://sitio-publico.test/", politica="no soy json"))

    assert "mal formada" in error


def test_mcp_destino_interno_bloqueado():
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="PANEL INTERNO")) as p_web:
        resolver = crear_resolver({"sitio-publico.test": ["127.0.0.1"]})
        red = RedSimulada()
        with servidor_mcp_en_proceso(resolver, red.crear_transporte) as p_mcp:
            host = HostDePrueba(p_mcp)
            error = ejecutar(host.invocar_esperando_error(
                f"http://sitio-publico.test:{p_web}/", politica=POLITICA_BASE))

    assert "egress_bloqueado" in error
    assert pedidos == []
    assert red.ips_fijadas == []


def test_mcp_host_fuera_de_allowlist():
    resolver = crear_resolver({"otro-sitio.test": [IP_PUBLICA_SIMULADA]})
    red = RedSimulada()
    with servidor_mcp_en_proceso(resolver, red.crear_transporte) as p_mcp:
        host = HostDePrueba(p_mcp)
        error = ejecutar(host.invocar_esperando_error(
            "http://otro-sitio.test/", politica=POLITICA_BASE))

    assert "egress_bloqueado" in error
    assert red.ips_fijadas == []


def test_mcp_error_no_enumera_la_allowlist():
    """
    §7.5: el mensaje de error vuelve al contexto del modelo y es superficie.
    No debe entregar el mapa de hosts permitidos ni de rangos prohibidos.
    """
    resolver = crear_resolver({"otro-sitio.test": [IP_PUBLICA_SIMULADA]})
    red = RedSimulada()
    with servidor_mcp_en_proceso(resolver, red.crear_transporte) as p_mcp:
        host = HostDePrueba(p_mcp)
        error = ejecutar(host.invocar_esperando_error(
            "http://otro-sitio.test/", politica=POLITICA_BASE))

    assert "sitio-publico.test" not in error


def test_mcp_sin_identidad_ni_tenant():
    """La tool no exige identidad hoy; el test documenta ese comportamiento."""
    pedidos = []
    with servidor_local(crear_handler(pedidos, cuerpo="CONTENIDO OK")) as p_web:
        resolver = crear_resolver({"sitio-publico.test": [IP_PUBLICA_SIMULADA]})
        red = RedSimulada()
        with servidor_mcp_en_proceso(resolver, red.crear_transporte) as p_mcp:
            host = HostDePrueba(p_mcp)
            resultado = ejecutar(host.invocar(
                f"http://sitio-publico.test:{p_web}/", politica=POLITICA_BASE))

    assert "CONTENIDO OK" in resultado["contenido"]


def test_mcp_rebinding_resiste_por_protocolo():
    def dns_rebinding(n):
        return [IP_PUBLICA_SIMULADA] if n == 1 else ["127.0.0.1"]

    with servidor_local(crear_handler([], cuerpo="CONTENIDO")) as p_web:
        resolver = crear_resolver({"sitio-publico.test": dns_rebinding})
        red = RedSimulada()
        with servidor_mcp_en_proceso(resolver, red.crear_transporte) as p_mcp:
            host = HostDePrueba(p_mcp)
            resultado = ejecutar(host.invocar(
                f"http://sitio-publico.test:{p_web}/", politica=POLITICA_BASE))

    assert resolver.llamadas == ["sitio-publico.test"]
    assert red.ips_fijadas == [IP_PUBLICA_SIMULADA]
    assert "CONTENIDO" in resultado["contenido"]