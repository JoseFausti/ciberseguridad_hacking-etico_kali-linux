from gpt4all import GPT4All

class IAagent:
    """
    Clase que representa a un agente de inteligencia artificial capaz de generar Google Dorks basados en descripciones proporcionadas por el usuario.
    
    Attributes:
        model (GPT4All): Modelo de generación de texto utilizado para generar Google Dorks.
    """

    def __init__(self, model="orca-mini-3b-gguf2-q4_0.gguf"):
        """
        Inicializa un nuevo agente de inteligencia artificial con el modelo especificado.

        Args:
            model (str): Nombre del modelo de GPT4All a utilizar. El valor por defecto es 'orca-mini-3b-gguf2-q4_0.gguf'.
        """
        self.model = GPT4All(model)

    def generate_gdork(self, description):
        """
        Genera un Google Dork basado en la descripción proporcionada.

        Args:
            description (str): Descripción proporcionada por el usuario para generar el Google Dork.

        Returns:
            str: Google Dork generado o None en caso de error.
        """
        prompt = self._build_prompt(description)
        try:
            output = self.model.generate(prompt)
            return output
        except Exception as e:
            print(f"Error al generar el Google Dork: {e}")
            return None
    
    def _build_prompt(self, description):
        """
        Construye el prompt para la generación del Google Dork basándose en la descripción proporcionada.

        Args:
            description (str): Descripción del Google Dork que necesita ser generado.

        Returns:
            str: Prompt construido para la generación del Google Dork.
        """
        return f"""
        Genera un Google Dork específico basado en la descripción del usuario. Un Google Dork utiliza operadores avanzados en motores de búsqueda para encontrar información específica que es difícil de encontrar mediante una búsqueda normal. Tu tarea es convertir la descripción del usuario en un Google Dork preciso. A continuación, se presentan algunos ejemplos de cómo deberías formular los Google Dorks basándote en diferentes descripciones:

        Descripción: Documentos PDF relacionados con la seguridad informática publicados en el último año.
        Google Dork: filetype:pdf "seguridad informática" after:2023-01-01

        Descripción: Presentaciones de Powerpoint sobre cambio climático disponibles en sitios .edu.
        Google Dork: site:.edu filetype:ppt "cambio climático"

        Descripción: Listas de correos electrónicos en archivos de texto dentro de dominios gubernamentales.
        Google Dork: site:.gov filetype:txt "email" | "correo electrónico"

        Ahora, basado en la siguiente descripción proporcionada por el usuario, genera el Google Dork correspondiente:

        Descripción: {description}
        """

if __name__ == "__main__":
    ia_agent = IAagent()
    print(ia_agent.generate_gdork("Listado de usuarios y passwords en el contenido de ficheros de texto."))