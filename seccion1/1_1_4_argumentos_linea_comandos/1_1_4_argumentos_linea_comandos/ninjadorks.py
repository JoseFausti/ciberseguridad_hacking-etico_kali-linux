from googlesearch import GoogleSearch
from dotenv import load_dotenv, set_key
import os
import argparse
import sys

def env_config():
    """
    Solicita al usuario la API KEY de Google y el ID del buscador personalizado
    y actualiza o crea un archivo .env con estos valores.
    """
    api_key = input("Introduce tu API KEY de Google: ")
    engine_id = input("Introduce el ID del buscador personalizado de Google: ")
    set_key(".env", "API_KEY_GOOGLE", api_key)
    set_key(".env", "SEARCH_ENGINE_ID", engine_id)
    print("Archivo .env configurado satisfactoriamente.")

def main(query, configure_env=None, start_page=1, pages=1, lang="lang_es"):
    """
    Realiza una búsqueda en Google utilizando una API KEY y un SEARCH ENGINE ID almacenados en un archivo .env.
    
    Args:
        query (str): Consulta de búsqueda que se realizará en Google.
        configure_env (bool, optional): Si es True, se solicita configurar el .env. Defaults to None.
        start_page (int, optional): Página inicial de los resultados de búsqueda. Defaults to 1.
        pages (int, optional): Número de páginas de resultados a retornar. Defaults to 1.
        lang (str, optional): Código de idioma para los resultados de búsqueda. Defaults to 'lang_es'.
    """
    # Verificar la existencia del archivo .env
    if configure_env or not os.path.exists(".env"):
        env_config()
        sys.exit(1)

    # Cargar las variables de entorno
    load_dotenv()

    # Extraer valores de las variables de entorno
    google_api_key = os.getenv("API_KEY_GOOGLE")
    search_engine_id = os.getenv("SEARCH_ENGINE_ID")

    # Verificar la disponibilidad de las claves de API
    if not google_api_key or not search_engine_id:
        print("ERROR: Falta la API_KEY o el SEARCH_ENGINE_ID. Por favor, ejecuta la opción --configure para configurar el archivo .env.")
        sys.exit(1)

    # Verificar la presencia de una consulta
    if not query:
        print("Indica una consulta con el comando -q. Utiliza el comando -h para mostrar la ayuda.")
        sys.exit(1)

    # Realizar la búsqueda en Google
    gsearch = GoogleSearch(google_api_key, search_engine_id)
    resultados = gsearch.search(query, start_page=start_page, pages=pages, lang=lang)
    print(resultados)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Herramienta para realizar búsquedas avanzadas en Google de forma automática.")
    parser.add_argument("-q", "--query", type=str, help="Especifica el dork que deseas buscar. Ejemplo: -q \"filetype:sql 'MySQL dump' (pass|password|passwd|pwd)\"")
    parser.add_argument("-c", "--configure", action="store_true", help="Configura o actualiza el archivo .env. Utiliza esta opción sin otros argumentos para configurar las claves.")
    parser.add_argument("--start-page", type=int, default=1, help="Página de inicio para los resultados de búsqueda. Por defecto es 1.")
    parser.add_argument("--pages", type=int, default=1, help="Número de páginas de resultados a retornar. Por defecto es 1.")
    parser.add_argument("--lang", type=str, default="lang_es", help="Código de idioma para los resultados de búsqueda. Por defecto es 'lang_es' (español).")
    
    args = parser.parse_args()

    main(query=args.query, 
         configure_env=args.configure, 
         start_page=args.start_page, 
         pages=args.pages, 
         lang=args.lang)