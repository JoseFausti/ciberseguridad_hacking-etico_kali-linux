import ipinfo
from dotenv import load_dotenv
import os
import sys
import folium

# Cargar las variables de entorno desde un archivo .env
load_dotenv()

# Obtener el token de acceso desde las variables de entorno
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")

# Dirección IP para obtener detalles geográficos
IP_ADDR = "79.116.189.204"

def draw_map(latitude, longitude, location, filename="map.html"):
    """
    Genera un mapa HTML utilizando la librería Folium.

    Args:
        latitude (float): Latitud del punto a marcar.
        longitude (float): Longitud del punto a marcar.
        location (str): Descripción de la ubicación para el marcador.
        filename (str): Nombre del archivo donde se guardará el mapa. Por defecto, "map.html".

    Returns:
        str: Ruta absoluta al archivo del mapa generado.
    """
    my_map = folium.Map(location=[latitude, longitude], zoom_start=9)
    folium.Marker([latitude, longitude], popup=location).add_to(my_map)
    my_map.save(filename)
    return os.path.abspath(filename)

def get_ip_details(ip_addr, access_token):
    """
    Obtiene detalles de geolocalización de una dirección IP utilizando la API de ipinfo.

    Args:
        ip_addr (str): La dirección IP de la cual obtener la información.
        access_token (str): El token de acceso para la API de ipinfo.

    Returns:
        dict: Un diccionario con todos los detalles obtenidos.

    Raises:
        SystemExit: Termina el script si hay un error al obtener los detalles de la IP.
    """
    try:
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails(ip_addr)
        return details.all
    except Exception as e:
        print(f"Error al obtener los detalles de la IP: {ip_addr}")
        sys.exit(1)


if __name__ == "__main__":
    details = get_ip_details(IP_ADDR, ACCESS_TOKEN)
    
    # Imprimir los detalles de la IP obtenidos
    for key, value in details.items():
        print(f"{key}: {value}")

    # Extraer latitud, longitud y ubicación del diccionario de detalles
    latitude = float(details["latitude"])
    longitude = float(details["longitude"])
    location = details.get("region", "Ubicación Desconocida")

    # Generar y guardar el mapa
    map_file_path = draw_map(latitude, longitude, location)
    print(f"Mapa guardado en: {map_file_path}")