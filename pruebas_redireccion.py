import httpx
import asyncio


async def main():
    print("=== SIN follow_redirects (comportamiento por defecto) ===")
    async with httpx.AsyncClient() as client:
        respuesta = await client.get("http://127.0.0.1:9002/")
        print("Codigo de estado:", respuesta.status_code)
        print("URL final:", respuesta.url)
        print("Contenido:", repr(respuesta.text))

    print("\n=== CON follow_redirects=True (a proposito) ===")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        respuesta = await client.get("http://127.0.0.1:9002/")
        print("Codigo de estado:", respuesta.status_code)
        print("URL final:", respuesta.url)
        print("Contenido:", repr(respuesta.text))


asyncio.run(main())