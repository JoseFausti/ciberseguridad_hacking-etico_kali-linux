import requests
import re
from selenium.webdriver.firefox.service import Service
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver import FirefoxOptions
from selenium.webdriver import Firefox
from selenium.webdriver.common.by import By 
from selenium.webdriver.support.ui import WebDriverWait

def has_valid_credentials_github():
    """Realiza un intento de login en GitHub de manera automática utilizando Selenium.
    
    Returns:
        bool: Retorna True si el login es exitoso, False si falla.
    """
    # Inicialización del driver de Firefox con opciones predeterminadas
    service = Service(GeckoDriverManager().install())
    options = FirefoxOptions()
    driver = Firefox(service=service, options=options)

    # Navegación a la página de login de GitHub
    driver.get("https://github.com/login")

    # Credenciales de usuario de prueba
    usuario = "testuser"
    password = "password"

    # Inserción de credenciales en los campos correspondientes
    driver.find_element(By.ID, "login_field").send_keys(usuario)
    driver.find_element(By.ID, "password").send_keys(password)

    # Envío del formulario de login
    driver.find_element(By.NAME, "commit").click()

    # Espera hasta que la página esté completamente cargada
    WebDriverWait(driver=driver, timeout=10).until(
        lambda x: x.execute_script("return document.readyState == 'complete'")
    )

    # Verificación de mensajes de error
    err_msg = "Incorrect username or password"
    errors = driver.find_elements(By.CLASS_NAME, "js-flash-alert")
    
    # Decisión basada en la presencia de mensajes de error
    if any(err_msg in e.text for e in errors):
        print("[!] El login no ha tenido éxito.")
        driver.close()
        return False
    else:
        print("[+] El login ha tenido éxito.")
        driver.close()
        return True
    
def has_valid_credentials(instance):
    """
    Verifica si una instancia de DVWA (Damn Vulnerable Web Application) tiene configuradas las credenciales por defecto.

    Args:
        instance (dict): Un diccionario que contiene la IP, el puerto y si el protocolo SSL está habilitado en la forma:
                         {'ip_str': '127.0.0.1', 'port': 80, 'ssl': True o False}

    Returns:
        bool: True si las credenciales por defecto son aceptadas, False en caso contrario.

    Raises:
        requests.exceptions.ConnectionError: Si no se puede establecer una conexión con la instancia DVWA.
        Exception: Si hay problemas al extraer el token CSRF de la página de login.
    """

    # Inicializa la sesión HTTP
    sess = requests.Session()
    proto = 'https' if 'ssl' in instance else 'http'
    login_page = f"{proto}://{instance['ip_str']}:{instance['port']}/login.php"

    # Intenta acceder a la página de login
    try:
        response = sess.get(login_page, verify=False)  # No verifica el certificado SSL del servidor
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Error al intentar conectarse al host {instance['ip_str']}: {e}")
        return False
    
    if response.status_code != 200:
        print(f"[!] Error en la respuesta del servidor. Respuesta: {response.status_code}")
        return False
    
    # Intenta obtener el token CSRF para la autenticación
    try:
        token = re.search(r"user_token' value='([0-9a-f]+)'", response.text).group(1)
    except Exception as e:
        print(f"[!] Error al obtener el token CSRF: {e}")
        return False

    # Envía los datos de login con las credenciales por defecto
    response = sess.post(
        login_page,
        data=f"username=admin&password=password&user_token={token}&Login=Login",
        allow_redirects=False,
        verify=False,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    # Evalúa si la respuesta indica un login exitoso
    if response.status_code == 302 and response.headers.get('Location') == 'index.php':
        return True
    else:
        return False


if __name__ == "__main__":
    resultado = has_valid_credentials_github()
    print(f"Resultado del login: {resultado}")