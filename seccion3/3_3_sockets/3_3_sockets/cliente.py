import socket

# Configuración inicial del socket para conexión con el servidor.
cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Establecimiento de conexión con el servidor local en el puerto especificado.
cliente.connect(('localhost', 12345))

try:
    # Bucle infinito para mantener la sesión de cliente activa.
    while True:
        # Recoger datos del usuario para enviar.
        datos = input("Introduce los datos para enviar: ")
        # Enviar los datos codificados al servidor.
        cliente.sendall(datos.encode())

    # Código para responder al servidor comentado.
    # mensaje = "Hola servidor".encode()
    # cliente.sendall(mensaje)
    # respuesta = cliente.recv(1024)
    # print("Respuesta del servidor:", respuesta.decode())

except KeyboardInterrupt:
    print("Cerrando la conexión con el servidor.")
    cliente.close()