from dotenv import load_dotenv
import os
from shodansearch import ShodanSearch
from login_automation import has_valid_credentials
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_results(resultados, index):
    """Obtiene y formatea los resultados de una búsqueda específica en Shodan.

    Args:
        resultados (dict): Diccionario que contiene los resultados de la búsqueda de Shodan.
        index (int): Índice del resultado actual dentro de la lista total de resultados.

    Returns:
        dict: Un diccionario que contiene información formateada del resultado, incluyendo
              índice, dirección IP, hostname, localización y si utiliza credenciales por defecto.
    """
    results = {
        "index": index,
        "data": f"\nResultado {index}\n" +
                f"Direccion IP: {resultados['ip_str']}\n" +
                f"Hostname: {resultados['hostnames']}\n" +
                f"Localizacion: {resultados['location']}\n" +
                f"Credenciales por defecto: {has_valid_credentials(resultados)}\n"
    }
    return results

def main():
    """
    Realiza una búsqueda utilizando la API de Shodan y procesa los resultados usando múltiples hilos.
    Imprime los resultados procesados y el tiempo total de procesamiento.
    """
    # Carga las variables de entorno desde el archivo .env
    load_dotenv()

    # Recupera la clave de API de Shodan desde las variables de entorno
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

    # Crea una instancia de ShodanSearch con la clave de API
    ssearch = ShodanSearch(SHODAN_API_KEY)

    # Realiza una búsqueda en Shodan con el título especificado y la primera página de resultados
    resultados = ssearch.search("title:dvwa", page=1)

    # Inicia el contador de tiempo
    t = time.perf_counter()

    # Lista para almacenar los 'futures' de los trabajos enviados al ejecutor
    workers = []

    # Utiliza un pool de hilos para procesar simultáneamente los resultados de búsqueda
    with ThreadPoolExecutor(max_workers=5) as executor:
        for i in range(5):
            # Envia el trabajo de procesamiento de resultados al pool y almacena el 'future'
            workers.append(executor.submit(get_results, resultados['matches'][i], i))

    # Espera a que todos los trabajos se completen y luego imprime sus resultados
    for worker in as_completed(workers):
        result = worker.result()
        print(result["data"])

    # Imprime el tiempo total de procesamiento
    print(f"Tiempo de procesamiento: {time.perf_counter() - t:.2f}s")

if __name__ == "__main__":
    main()