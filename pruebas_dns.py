import socket
import ipaddress


def resolver_todas_las_ips(host: str) -> list[str]:
    """
    Resuelve un dominio a TODAS sus direcciones IP (no solo la primera).
    Esto es importante: el informe (6.2 y 7.3) advierte que hay que
    validar TODOS los registros que devuelve la resolucion, no el primero,
    porque un ataque barato es hacer que un dominio resuelva a dos IPs
    (una publica, una interna) y dejar que la biblioteca elija.
    """
    resultados = socket.getaddrinfo(host, None) # devuelve que IPs corresponden al dominio
    # getaddrinfo devuelve tuplas con mucha info; nos interesa el IP,
    # que esta en la posicion [4][0] de cada tupla - expresion regular
    ips = {r[4][0] for r in resultados}  # set para eliminar duplicados
    return list(ips)

# validacion de IPs privadas/internas
def es_ip_privada_o_interna(ip_texto: str) -> bool:
    ip = ipaddress.ip_address(ip_texto)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )

# recorro todas las IPs devueltas (no solo la primera) rechazo el host si es privada/interna
def host_es_seguro(host: str) -> bool:
    """
    Devuelve True solo si TODAS las IPs a las que resuelve el host
    son publicas (ninguna es interna/privada).
    """
    ips = resolver_todas_las_ips(host)
    print(f"  {host} resolvio a: {ips}")  # ver el proceso real

    for ip in ips:
        if es_ip_privada_o_interna(ip):
            print(f"  RECHAZADO: {ip} es privada/interna")
            return False

    return True


# Pruebas
print("example.com:")
print(host_es_seguro("example.com"))

print("\nlocalhost:")
print(host_es_seguro("localhost"))