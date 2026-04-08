import shodan

class ShodanSearch:
    """Clase para realizar búsquedas utilizando la API de Shodan.

    Attributes:
        client (shodan.Shodan): Cliente de Shodan configurado con una clave API.
    """

    def __init__(self, api_key):
        """Inicializa la instancia de ShodanSearch con la clave API proporcionada.

        Args:
            api_key (str): Clave API de Shodan para autenticar las peticiones a la API.
        """
        self.client = shodan.Shodan(api_key)

    def search(self, query, page=1):
        """Realiza una consulta en Shodan y devuelve una página de resultados.

        Args:
            query (str): Consulta de búsqueda para enviar a la API de Shodan.
            page (int, optional): Número de página de los resultados a recuperar. Por defecto es 1.

        Returns:
            dict: Un diccionario con los resultados de la búsqueda si es exitosa.
        """
        try:
            results = self.client.search(query, page=page)
            return results
        except Exception as e:
            print('Error al realizar la petición a la API de Shodan:', e)