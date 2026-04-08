import requests


class GoogleSearch:
    """Clase para realizar búsquedas usando la API de SerpApi.
    
    Esta clase permite a los usuarios ejecutar búsquedas en Google utilizando SerpApi,
    manejando la paginación de resultados y permitiendo configurar el idioma de los resultados.

    Attributes:
        api_key (str): Clave de API para acceder a SerpApi.
    """

    def __init__(self, api_key):
        """Inicializa una nueva instancia de GoogleSearch con la clave de API.

        Args:
            api_key (str): La clave de API para acceder a SerpApi.
        """
        self.api_key = api_key

    def search(self, query, start_page=1, pages=1, lang="lang_es"):
        """Realiza una búsqueda en Google utilizando SerpApi.

        La función gestiona la paginación y la recuperación de los resultados de la búsqueda,
        procesando cada página según se especifica.

        Args:
            query (str): Texto de la consulta para la búsqueda.
            start_page (int): Página inicial desde la que empezar la búsqueda.
            pages (int): Número de páginas de resultados a recuperar.
            lang (str): Idioma de los resultados, en formato de código de idioma.

        Returns:
            list[dict]: Lista de resultados personalizados de la búsqueda, cada uno como un diccionario.

        Raises:
            Exception: Si la respuesta de la API tiene un estado HTTP que no es 200.
        """
        final_results = []
        results_per_page = 10  # Google muestra 10 resultados por página
        for page in range(pages):
            start_index = (start_page - 1) * results_per_page + 1 + (page * results_per_page)
            url = f"https://serpapi.com/search?api_key={self.api_key}&engine=google&q={query}&start={start_index}&lr={lang}"
            response = requests.get(url)

            if response.status_code == 200:
                data = response.json()
                results = data.get("organic_results", [])
                cresults = self.custom_results(results)
                final_results.extend(cresults)
            else:
                error_msg = f"Error obtaining page {page + 1}: HTTP {response.status_code}"
                print(error_msg)
                raise Exception(error_msg)

        return final_results

    def custom_results(self, results):
        """Procesa y filtra los resultados brutos de SerpApi.

        Args:
            results (list[dict]): Lista de resultados brutos de la API.

        Returns:
            list[dict]: Lista de resultados procesados, cada uno con título, descripción y enlace.
        """
        custom_results = []
        for result in results:
            cresult = {
                "title": result.get("title"),
                "description": result.get("snippet"),
                "link": result.get("link")
            }
            custom_results.append(cresult)
        return custom_results