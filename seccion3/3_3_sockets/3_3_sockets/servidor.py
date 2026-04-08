import socket

# Configuración inicial del servidor TCP utilizando IPv4 y protocolo TCP.
servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Asignación del socket a una dirección local y puerto específico.
servidor.bind(('localhost', 12345))

# El servidor comienza a escuchar conexiones con un backlog default.
servidor.listen()

print("Esperando conexiones....")

# Acepta una conexión entrante.
conexion, direccion = servidor.accept()

# Gestión de la conexión establecida.
with conexion:
    print(f"Conectado a: {direccion}")
    while True:
        # Recepción de datos del cliente.
        datos = conexion.recv(1024)
        if not datos:
            break
        print(f"Datos recibidos del cliente: {datos.decode()}")

        # Código para responder al cliente comentado.
        # mensaje = "Hola cliente".encode()
        # conexion.sendall(mensaje)

# Cierre de la conexión al salir del bucle.
conexion.close()
