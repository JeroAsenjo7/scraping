import asyncio
import httpx # para hacer pedidos HTTP (GET, POST, etc) a otros servidores

# Transporte es la capa httpx que se encarga de abrir sockets, resolver DNS, etc.
# reutilizare toda esa logica para luego sobreescribir y utilice una IP fija
class TransporteIPFija(httpx.AsyncHTTPTransport): 
    """
    Transporte que fuerza la conexion a una IP especifica,
    sin importar a que dominio apunte la URL. El dominio original
    se preserva en la cabecera Host.
    """

    def __init__(self, ip_destino: str, **kwargs): # el constructor recibe la IP que va a forzar en cada pedido
        super().__init__(**kwargs) # llama al constructor de la clase padre (AsyncHTTPTransport) para inicializar todo lo demas
        self.ip_destino = ip_destino # almacenamos la IP destino

    # metodo que se llama para cada pedido HTTP asincronico (httpx.get, httpx.post, etc)
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host_original = request.url.host
        # Preservamos el dominio original en la cabecera Host
        request.headers["Host"] = host_original
        # Reescribimos la URL para que apunte directo a la IP fija
        request.url = request.url.copy_with(host=self.ip_destino)
        # La url tiene una ip en el campo host en lugar de un nombre de dominio
        # la libreria no tiene ningun nombre que resolver y se conecta directo a esa IP
        return await super().handle_async_request(request)


async def main():
    # Usamos un dominio que NI SIQUIERA EXISTE en ningun DNS real.
    # Si esto funciona, confirma que httpx nunca intento resolverlo:
    # fuimos nosotros quienes decidimos la IP real de conexion.
    transporte = TransporteIPFija(ip_destino="127.0.0.1")

    async with httpx.AsyncClient(transport=transporte) as client:
        respuesta = await client.get("http://este-dominio-no-existe.test:9001/")
        print("Codigo de estado:", respuesta.status_code)
        print("Contenido recibido:")
        print(respuesta.text)


asyncio.run(main())