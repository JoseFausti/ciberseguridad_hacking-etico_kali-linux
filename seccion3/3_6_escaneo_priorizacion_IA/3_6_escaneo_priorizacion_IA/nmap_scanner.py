import nmap
from openai import OpenAI
from dotenv import load_dotenv

def hosts_scan(network):
    """
    Realiza un escaneo rápido de los hosts para determinar cuáles están activos dentro de una red específica.

    Args:
        network (str): La dirección de la red o el rango de IP a escanear.

    Returns:
        list: Lista de direcciones IP de hosts que están activos.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts

def services_scan(network):
    """
    Escanea los servicios y versiones de los mismos en los hosts activos de una red.

    Args:
        network (str): La dirección de la red o el rango de IP a escanear.

    Returns:
        dict: Diccionario que mapea cada host activo a los protocolos y servicios con sus respectivas versiones.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sV')
    network_data = {}
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            network_data[host] = {}
            for proto in nm[host].all_protocols():
                network_data[host][proto] = {}
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['product'] + " " + nm[host][proto][port]['version']
                    network_data[host][proto][port] = {'service': service, 'version': version}
    return network_data

def priorizar_hosts(network_data):
    """
    Utiliza un modelo de IA para evaluar la vulnerabilidad de los hosts en base a los datos del escaneo de servicios,
    y proporciona recomendaciones de acciones de explotación.

    Args:
        network_data (dict): Diccionario con los datos de los hosts y servicios escaneados.

    Returns:
        str: Respuesta generada por el modelo de IA con la priorización de los hosts y recomendaciones.
    """
    load_dotenv()
    client = OpenAI()
    chat_completion = client.chat.completions.create(
        messages=[
                {"role": "system", "content": "Eres un experto en Ciberseguridad y en gestión y priorización de vulnerabilidades."},
                {"role": "user", "content": f"Teniendo en cuenta el siguiente descubrimiento de hosts, servicios y versiones, ordena los hosts de más vulnerable a menos vulnerable y propón los siguientes pasos para la fase de explotación de cada host.\n\n{network_data}"},
            ],
        model="gpt-4-0125-preview",
    )
    return chat_completion.choices[0].message.content


if __name__ == "__main__":
    # Ejemplo de uso de las funciones para escanear hosts y servicios en una red.
    network_data = services_scan('192.168.138.0/24')
    print(priorizar_hosts(network_data))