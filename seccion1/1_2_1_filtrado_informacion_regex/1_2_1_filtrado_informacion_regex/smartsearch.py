import os
import re
import argparse

class SmartSearch:
    """Clase que permite realizar búsquedas en archivos de un directorio mediante expresiones regulares.

    Attributes:
        dir_path (str): La ruta del directorio donde se encuentran los archivos.
        files (dict): Diccionario que contiene el nombre de cada archivo y su contenido como clave y valor respectivamente.
    """

    def __init__(self, dir_path):
        """Inicializa la clase SmartSearch.

        Args:
            dir_path (str): Ruta del directorio donde se realizarán las búsquedas.
        """
        self.dir_path = dir_path
        self.files = self._read_files()

    def _read_files(self):
        """Lee los archivos de un directorio y guarda su contenido en un diccionario.

        Returns:
            dict: Diccionario donde cada clave es el nombre de un archivo y cada valor es su contenido.
        """
        files = {}
        # Iterar sobre todos los archivos en el directorio especificado
        for archivo in os.listdir(self.dir_path):
            file_path = os.path.join(self.dir_path, archivo)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    files[archivo] = f.read()
            except Exception as e:
                print(f"Error al leer el archivo {file_path}: {e}")
        return files

    def regex_search(self, regex):
        """Realiza una búsqueda utilizando una expresión regular en todos los archivos del directorio.

        Args:
            regex (str): La expresión regular utilizada para la búsqueda.

        Returns:
            dict: Un diccionario donde cada clave es un archivo y cada valor es una lista de coincidencias encontradas.
        """
        coincidencias = {}
        for file, text in self.files.items():
            respuesta = ""
            while respuesta not in ("y", "n", "yes", "no"):
                respuesta = input(f"El archivo {file} tiene una longitud de {len(text)} caracteres, ¿seguro que deseas continuar? (y/n): ")
            if respuesta in ("n", "no"):
                continue
            matches = re.findall(regex, text, re.IGNORECASE)
            if matches:
                coincidencias[file] = matches
        return coincidencias


if __name__ == "__main__":
    # Configuración de los argumentos del programa
    parser = argparse.ArgumentParser(description="Esta herramienta permite realizar búsquedas en archivos utilizando expresiones regulares.")
    parser.add_argument("file", type=str, help="Directorio en el que realizar la búsqueda.")
    parser.add_argument("-r", "--regex", type=str, help="La expresión regular para realizar la búsqueda.")
    args = parser.parse_args()

    if args.regex:
        searcher = SmartSearch(args.file)
        resultados = searcher.regex_search(args.regex)
        print()
        for file, results in resultados.items():
            print(file)
            for r in results:
                print(f"\t- {r}")