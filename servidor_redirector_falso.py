from http.server import BaseHTTPRequestHandler, HTTPServer


class HandlerRedirector(BaseHTTPRequestHandler): # clase que entiende el protoclo HTTP y responde a pedidos
    def do_GET(self):
        # Simula un sitio publico que fue comprometido (o mal configurado)
        # y redirige hacia un recurso interno.
        self.send_response(302) # 302 significa esto se movio, anda a otro lado
        self.send_header("Location", "http://127.0.0.1:9001/") # a donde redirige (recurso interno)
        self.end_headers()

    def log_message(self, format, *args):
        print(f"[SERVIDOR REDIRECTOR] Recibi un pedido: {self.path}")


if __name__ == "__main__":
    servidor = HTTPServer(("127.0.0.1", 9002), HandlerRedirector)
    print("Servidor redirector simulado escuchando en http://127.0.0.1:9002")
    servidor.serve_forever()