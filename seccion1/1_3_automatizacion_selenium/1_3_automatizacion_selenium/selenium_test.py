from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def main():
    """
    Inicia un WebDriver, realiza una búsqueda en Google y extrae los resultados.

    Este script automatiza un navegador para buscar un nombre en Google, acepta cookies,
    envía una cadena de texto en el cuadro de búsqueda, y extrae los títulos, enlaces y
    descripciones de los primeros resultados de búsqueda mostrados.

    Utiliza Firefox como navegador mediante Selenium WebDriver.
    """
    # Configuración inicial de WebDriver para Chrome
    # service = Service(ChromeDriverManager().install())
    # options = webdriver.ChromeOptions()
    # browser = webdriver.Chrome(service=service, options=options)

    # Configuración inicial de WebDriver para Firefox
    service = Service(GeckoDriverManager().install())
    options = webdriver.FirefoxOptions()
    browser = webdriver.Firefox(service=service, options=options)

    try:
        # Acceso a Google
        browser.get('http://www.google.com')

        # Manejo de cookies
        accept_cookies(browser)

        # Búsqueda de nombre
        perform_search(browser, 'Santiago Hernandez Ramos')

        # Extracción de resultados
        extract_results(browser)

    finally:
        # Cierre del navegador
        browser.quit()

def accept_cookies(browser):
    """
    Espera y acepta el botón de cookies en la página de Google.

    Args:
        browser (webdriver.Firefox): Instancia del navegador para interactuar con la web.
    """
    try:
        accept_button = WebDriverWait(browser, 10).until(
            EC.element_to_be_clickable((By.ID, 'L2AGLb'))
        )
        accept_button.click()
    except Exception as e:
        print("Error al encontrar o hacer clic en el botón de aceptar: ", e)

def perform_search(browser, query):
    """
    Encuentra el cuadro de búsqueda de Google y envía una cadena de texto para buscar.

    Args:
        browser (webdriver.Firefox): Instancia del navegador para interactuar con la web.
        query (str): Cadena de texto a buscar.
    """
    search_box = browser.find_element(By.NAME, 'q')
    search_box.send_keys(query + Keys.ENTER)
    time.sleep(5)  # Espera para la carga completa de los resultados

def extract_results(browser):
    """
    Extrae los enlaces, títulos y descripciones de los primeros resultados de búsqueda en Google.

    Args:
        browser (webdriver.Firefox): Instancia del navegador para interactuar con la web.
    """
    results = browser.find_elements(By.CSS_SELECTOR, 'div.g')
    for result in results:
        try:
            title = result.find_element(By.CSS_SELECTOR, 'h3').text
            link = result.find_element(By.TAG_NAME, 'a').get_attribute('href')
            description = result.find_element(By.CSS_SELECTOR, 'div.VwiC3b').text
            print(f'Título: {title}\nEnlace: {link}\nDescripción: {description}\n')
        except Exception as e:
            print("Un elemento no pudo ser extraído debido a una excepción.")
            continue

if __name__ == "__main__":
    main()