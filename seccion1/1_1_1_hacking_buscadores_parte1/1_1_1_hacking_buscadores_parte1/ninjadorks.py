import requests

# Constantes para configurar la API de búsqueda personalizada de Google
API_KEY_GOOGLE = 'Aqui tu API KEY de Google'
SEARCH_ENGINE_ID = 'Aqui tu Search Engine ID para Google'

# Configuración de la consulta y parámetros de búsqueda
query = 'filetype:sql "MySQL dump" (pass|password|passwd|pwd)'
page = 1
lang = "lang_es"

# Construcción de la URL para la API de Google Custom Search
url = f"https://www.googleapis.com/customsearch/v1?key={API_KEY_GOOGLE}&cx={SEARCH_ENGINE_ID}&q={query}&start={page}&lr={lang}"

# Realizar la solicitud HTTP GET y convertir la respuesta en JSON
response = requests.get(url)
data = response.json()

# Recuperar la lista de resultados de la respuesta
results = data.get("items", [])  # Uso de get para evitar KeyError si 'items' no existe

# Iterar sobre cada resultado e imprimir los detalles relevantes
for result in results:
    print("------- Nuevo resultado -------")
    print(f"Título: {result.get('title')}")
    print(f"Descripción: {result.get('snippet')}")
    print(f"Enlace: {result.get('link')}")
    print("-------------------------------")
