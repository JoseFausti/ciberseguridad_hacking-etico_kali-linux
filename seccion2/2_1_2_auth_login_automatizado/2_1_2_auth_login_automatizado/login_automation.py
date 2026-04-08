import requests
import re

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