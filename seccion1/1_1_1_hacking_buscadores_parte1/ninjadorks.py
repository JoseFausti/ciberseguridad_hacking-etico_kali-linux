import requests

# Constantes para configurar la API de SerpApi
API_KEY_SERPAPI = 'Aqui tu API KEY de SerpApi'

# Configuración de la consulta y parámetros de búsqueda
query = 'filetype:sql "MySQL dump" (pass|password|passwd|pwd)'
page = 1
lang = "lang_es"

# Construcción de la URL para la API de SerpApi
url = f"https://serpapi.com/search?api_key={API_KEY_SERPAPI}&engine=google&q={query}&start={page}&lr={lang}"

# Realizar la solicitud HTTP GET y convertir la respuesta en JSON
response = requests.get(url)
data = response.json()

# Recuperar la lista de resultados de la respuesta
results = data.get("organic_results", [])  # SerpApi usa 'organic_results' en lugar de 'items'

# Iterar sobre cada resultado e imprimir los detalles relevantes
for result in results:
    print("------- Nuevo resultado -------")
    print(f"Título: {result.get('title')}")
    print(f"Descripción: {result.get('snippet')}")
    print(f"Enlace: {result.get('link')}")
    print("-------------------------------")