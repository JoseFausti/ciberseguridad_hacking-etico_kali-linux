import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import folium
from geopy.geocoders import Photon

def obtener_info_telefono(numero_telefono):
    """
    Obtiene información de geolocalización y operador para un número de teléfono específico.

    Args:
        numero_telefono (str): Número de teléfono en formato string.

    Returns:
        dict: Diccionario que contiene la información del número de teléfono como
              el número en formato internacional, país, operador y zona horaria asociados.
    """
    # Parsear el número de teléfono con el código de país "ES" para España
    numero = phonenumbers.parse(numero_telefono, "ES")

    # Obtener la zona horaria del número
    zona_horaria = timezone.time_zones_for_number(numero)

    # Obtener la descripción del país o región del número
    pais = geocoder.description_for_number(numero, "es")

    # Obtener el operador de telefonía asociado al número
    operador = carrier.name_for_number(numero, "es")

    # Crear un diccionario con la información obtenida
    info = {
        "Numero": phonenumbers.format_number(numero, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "Pais": pais,
        "Operador": operador,
        "Zona horaria": zona_horaria
    }
    return info

def pintar_mapa(localizacion, filename="phone_map.html"):
    """
    Construye y guarda un mapa HTML mostrando la localización geográfica de un número de teléfono.

    Args:
        localizacion (str): Localización geográfica a ser mostrada en el mapa.
        filename (str): Nombre del archivo HTML donde se guardará el mapa. Por defecto, 'phone_map.html'.
    """
    # Crear un objeto geolocalizador usando el servicio Photon
    geolocator = Photon(user_agent="geoapiExercise")
    location = geolocator.geocode(localizacion)

    # Inicializar un mapa en la localización obtenida con un nivel de zoom inicial
    mapa = folium.Map(location=[location.latitude, location.longitude], zoom_start=10)

    # Añadir un marcador en la ubicación obtenida con un popup
    folium.Marker([location.latitude, location.longitude], popup=localizacion).add_to(mapa)

    # Guardar el mapa en el archivo HTML especificado
    mapa.save(filename)
    print(f"Mapa guardado en: {filename}")

if __name__ == "__main__":
    # Ejemplo de uso del script
    numero = "689545600"
    info = obtener_info_telefono(numero)
    print(info)

    pintar_mapa(info["Pais"])
