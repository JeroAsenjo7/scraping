""" Pruebas con direcciones IP utilizando la libreria ipaddress """
import ipaddress

def es_ip_privada_o_interna(ip_texto: str) -> bool:
    ip = ipaddress.ip_address(ip_texto) # convierte el string en un objeto (IPv4Address o IPv6Address)
    return (
        ip.is_private # True si es un rango privado (10.x, 192.168.x, 172.16-31.x, etc.)
        or ip.is_loopback # True para 127.0.0.1 y ::1
        or ip.is_link_local # True para 169.254.x.x (¡acá cae el endpoint de metadata cloud!) y fe80::/10
        or ip.is_reserved # True para IPs reservadas por el IETF para usos de prueba o futuros
        or ip.is_multicast # True para rangos de transmisión en grupo (IPv4: 224.0.0.0/4, IPv6: ff00::/8).
    )

# Pruebas rápidas
# Pruebas rápidas
print(es_ip_privada_o_interna("127.0.0.1"))        # True (loopback)
print(es_ip_privada_o_interna("192.168.1.5"))       # True (privada)
print(es_ip_privada_o_interna("169.254.169.254"))   # True (link-local, metadata cloud)
print(es_ip_privada_o_interna("93.184.216.34"))     # False (IP publica real, ej. example.com)