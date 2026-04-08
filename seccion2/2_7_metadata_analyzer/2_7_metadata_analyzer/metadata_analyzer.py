import re
from abc import ABC, abstractmethod
from PIL import Image
import mimetypes
from pdfminer.high_level import extract_text
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
import docx

class MetadataExtractor(ABC):
    """Clase abstracta base para extractores de metadatos de diferentes tipos de archivos."""

    @abstractmethod
    def extract(self, filepath):
        """Extrae los metadatos de un archivo dado su ruta.
        
        Args:
            filepath (str): Ruta al archivo del cual se extraerán los metadatos.

        Returns:
            dict: Diccionario con los metadatos extraídos.
        """
        pass

class ImageMetadataExtractor(MetadataExtractor):
    """Extractor de metadatos para imágenes."""

    def extract(self, filepath):
        """Implementación para extraer metadatos de imágenes."""
        with Image.open(filepath) as img:
            if img.format in ['JPG', 'JPEG']:
                exif = img._getexif()
                if exif:
                    return {Image.ExifTags.TAGS.get(key, key): value
                            for key, value in exif.items() if key in Image.ExifTags.TAGS}
                else:
                    return {"Error": "No EXIF metadata found."}
            elif img.format in ['PNG']:
                if img.info:
                    return img.info
                else:
                    return {"Error": "No metadata found."}
            else:
                return {"Error": "Unsupported image format."}
            
class PdfMetadataExtractor(MetadataExtractor):
    """Extractor de metadatos para documentos PDF."""

    def extract(self, filepath):
        """Implementación para extraer metadatos de archivos PDF."""
        metadata = {}
        with open(filepath, 'rb') as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)
            if doc.info:
                for info in doc.info:
                    for key, value in info.items():
                        if isinstance(value, bytes):
                            try:
                                decoded_value = value.decode('utf-16be')
                            except UnicodeDecodeError:
                                decoded_value = value.decode('utf-8', errors='ignore')
                        else:
                            decoded_value = value
                        metadata[key] = decoded_value
            text = extract_text(filepath)
            metadata["Emails"] = self._extract_emails(text)
        return metadata

    def _extract_emails(self, text):
        """Extrae direcciones de email de un texto dado usando expresiones regulares.
        
        Args:
            text (str): Texto del cual extraer direcciones de email.

        Returns:
            list: Lista de direcciones de email encontradas.
        """
        email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(email_regex, text)
    

class DocxMetadataExtractor(MetadataExtractor):
    """Extractor de metadatos para documentos DOCX."""

    def extract(self, filepath):
        """Implementación para extraer metadatos de archivos DOCX."""
        doc = docx.Document(filepath)
        prop = doc.core_properties
        attributes = [
            "author", "category", "comments", "content_status",
            "created", "identifier", "keywords", "last_modified_by",
            "language", "modified", "subject", "title", "version"
        ]
        metadata = {attr: getattr(prop, attr, None) for attr in attributes}
        return metadata
            
class MetadataExtractorFactory:
    """Fábrica para crear extractores de metadatos basados en el tipo MIME del archivo."""

    @staticmethod
    def get_extractor(filepath):
        """Determina el extractor apropiado basado en el tipo MIME del archivo.
        
        Args:
            filepath (str): Ruta al archivo.

        Returns:
            MetadataExtractor: Instancia del extractor apropiado.

        Raises:
            ValueError: Si el tipo de archivo no es soportado.
        """
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type:
            if mime_type.startswith('image'):
                return ImageMetadataExtractor()
            if mime_type == 'application/pdf':
                return PdfMetadataExtractor()
            if mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                return DocxMetadataExtractor()
        raise ValueError("Unsupported file type")

def extract_metadata(filepath):
    """Extrae metadatos de un archivo dado su tipo.

    Args:
        filepath (str): Ruta completa al archivo del que se extraerán los metadatos.

    Returns:
        dict: Diccionario con los metadatos extraídos.
    """
    extractor = MetadataExtractorFactory.get_extractor(filepath)
    return extractor.extract(filepath)