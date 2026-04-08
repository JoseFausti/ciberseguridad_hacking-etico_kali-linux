from dotenv import load_dotenv
import os
from googlesearch import GoogleSearch

# Cargar las variables de entorno desde el archivo .env para garantizar la seguridad y configurabilidad.
load_dotenv()

# Obtener las claves de configuración desde las variables de entorno.
API_KEY_SERPAPI = os.getenv("API_KEY_SERPAPI")

# Definir la consulta de búsqueda que será usada para encontrar información específica en Google.
query = 'filetype:sql "MySQL dump" (pass|password|passwd|pwd)'

# Crear una instancia de GoogleSearch con la API de SerpApi.
gsearch = GoogleSearch(API_KEY_SERPAPI)

# Realizar la búsqueda con la consulta definida, especificando el número de páginas a recuperar.
resultados = gsearch.search(query, pages=2)

# Imprimir los resultados obtenidos de la búsqueda.
print(resultados)