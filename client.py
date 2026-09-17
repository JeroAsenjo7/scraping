import asyncio # libreria estandar de py para manejar asincronismo
from mcp import ClientSession # clase para manejar la sesion con el servidor
from mcp.client.streamable_http import streamablehttp_client # funcion para abrir un cliente streamable-http


async def main(): # async porque dentro usare await (esperar respuestas de la red)
    url_servidor = "http://127.0.0.1:8000/mcp" # isntancio mi propia url /mcp -> ruta donde vive el servidor

    async with streamablehttp_client(url_servidor) as (read, write, _): #conexion htpp .leer datos (raead) .escribir datos (write)
        async with ClientSession(read, write) as session: # creo la sesion: objeto con el que interactuo 
            await session.initialize() # inicializo la sesion

            # Listamos las tools disponibles (esto es lo que vería un agente)
            tools = await session.list_tools()
            print("Tools disponibles:", [t.name for t in tools.tools]) # imprimo solo los nombres de las tools disponibles

            # --- Pedido normal (caso normal, como antes) ---
            # Invocamos la tool con una URL pública normal
            # llamo la tool "obtener_contenido_web" con el argumento url
            print("\n=== Pedido 1: URL publica normal ===")
            resultado = await session.call_tool(
                "obtener_contenido_web",
                arguments={"url": "https://example.com"}
            )
            print(resultado.content[0].text[:300])

            # --- Pedido de ataque: simula que el modelo fue enganado ---
            # para apuntar a un recurso interno que NUNCA deberia ser
            # alcanzable desde afuera de la red.
            print("\n=== Pedido 2: intento de acceder a recurso INTERNO ===")
            resultado_ataque = await session.call_tool(
                "obtener_contenido_web",
                arguments={"url": "http://127.0.0.1:9001"}
            )
            print(resultado_ataque.content[0].text)

            # --- Pedido 3: URL publica que redirige a un recurso interno ---
            print("\n=== Pedido 3: URL publica que REDIRIGE a un interno ===")
            resultado_redirect = await session.call_tool(
                "obtener_contenido_web",
                arguments={"url": "http://127.0.0.1:9002/"}
            )
            print(resultado_redirect.content[0].text)

            # --- Pedido 4: dominio "publico" que redirige a un interno ---
            print("\n=== Pedido 4: dominio publico-falso que REDIRIGE a interno ===")
            resultado_redirect2 = await session.call_tool(
                "obtener_contenido_web",
                arguments={"url": "http://sitio-publico-falso.test:9002/"}
            )
            print(resultado_redirect2.content[0].text)

asyncio.run(main())