import whois

def obtener_informacion_whois(dominio):
    """
    Obtiene y retorna la información WHOIS de un dominio especificado.

    Args:
        dominio (str): El nombre de dominio para el cual se requiere la información WHOIS.

    Returns:
        whois.parser.WhoisEntry: Objeto que contiene la información WHOIS del dominio.
    
    Raises:
        whois.exceptions.WhoisCommandFailed: Si la consulta WHOIS falla.
        ValueError: Si el nombre de dominio no es válido o está vacío.
    """
    if not dominio:
        raise ValueError("El nombre de dominio no puede estar vacío.")

    response = whois.whois(dominio)  # Realiza la consulta WHOIS.
    return response

if __name__ == "__main__":
    # Nombre del dominio para realizar la consulta WHOIS.
    nombre_dominio = "udemy.com"

    try:
        # Obtención de la información WHOIS para el dominio especificado.
        informacion_whois = obtener_informacion_whois(nombre_dominio)
        print(informacion_whois)  # Muestra la información WHOIS en la consola.
    except Exception as e:
        print(f"Error al obtener la información WHOIS: {e}")