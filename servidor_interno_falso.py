from http.server import BaseHTTPRequestHandler, HTTPServer # libreria para levantar un servidor Http simple


class HandlerInterno(BaseHTTPRequestHandler): # clase que entiende el protoclo HTTP y responde a pedidos
    def do_GET(self): # do_get es un método y se ejecuta cada vez que llega un pedido GET - si fuera POST seria do_POST
        # envio el codigo de estado 200 (OK), luego aviso que el contenido sera texto plano y finalizo los headers.
        self.send_response(200) 
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        mensaje = ( # gurado el contenido de la respuesta (texto inventado)
            "PANEL INTERNO - CONFIDENCIAL\n"
            "Este recurso NUNCA deberia ser accesible desde afuera de la red.\n"
            "usuario_admin=admin\n"
            "clave_admin=SuperSecreta123\n"
        )
        self.wfile.write(mensaje.encode("utf-8"))

    def log_message(self, format, *args):
        # Para que se vea en la terminal cada vez que alguien pega
        print(f"[SERVIDOR INTERNO] Recibi un pedido: {self.path}")


if __name__ == "__main__":
    servidor = HTTPServer(("127.0.0.1", 9001), HandlerInterno) # creo el servidor HTTP 9001 en localhost
    print("Servidor interno simulado escuchando en http://127.0.0.1:9001")
    servidor.serve_forever() # lo deja escuchando indefinidamente hasta que se cierre el proceso, lo corto con Ctrl+C en la terminal