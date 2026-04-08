from metadata_analyzer import extract_metadata

def display_metadata(filepath):
    """Extrae y muestra los metadatos de un archivo.

    Args:
        filepath (str): Ruta del archivo del cual se extraerán los metadatos.
    """
    try:
        metadata = extract_metadata(filepath)
        for key, value in metadata.items():
            print(f"{key}: {value}")
    except FileNotFoundError:
        print("Error: El archivo especificado no fue encontrado.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")


if __name__ == "__main__":
    filepath = "/home/kali/python_hacking/seccion2/2_7_metadata_analyzer/Descargas/DSCN0010.jpg"
    display_metadata(filepath)