from dotenv import load_dotenv
import nmap
import os
import json
from openai import OpenAI
from jinja2 import Environment, FileSystemLoader

# Cargar las variables de entorno desde el archivo .env para garantizar la seguridad y configurabilidad.
load_dotenv()

def hosts_scan(network):
    """ Realiza un escaneo de hosts activos dentro de una red específica utilizando nmap.

    Args:
        network (str): La red a escanear, especificada en notación CIDR (ej. '192.168.1.0/24').

    Returns:
        list: Una lista de direcciones IP de los hosts que están activos en la red.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts

def services_scan(network):
    """ Realiza un escaneo de los servicios en los hosts activos de una red especificada.

    Args:
        network (str): La red a escanear, en notación CIDR.

    Returns:
        dict: Un diccionario donde cada clave es una dirección IP de un host activo
              y cada valor es otro diccionario que describe los protocolos y los
              puertos abiertos, junto con el servicio y la versión de dicho servicio
              que se está ejecutando en cada puerto.
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

def prepare_data(network_data):
    """Reduce y normaliza los datos para enviarlos a la IA."""

    IMPORTANT_PORTS = {21, 22, 23, 80, 443, 3306, 3389}
    lines = []

    for host, protocols in network_data.items():
        for proto, ports in protocols.items():
            for port, info in ports.items():
                if port in IMPORTANT_PORTS:
                    service = info["service"]
                    version = info["version"].replace(" ", "_")
                    lines.append(f"{host}:{port} {service} {version}")

    return "\n".join(lines[:40])

def prioritize_hosts(prepared_data):
    """Envía los datos a OpenAI y obtiene priorización.

    Args:
        prepared_data (str): Datos preparados para enviar a la IA.

    Returns:
        str: Priorización de los hosts.
    """

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""
        You are a penetration tester.
        Analyze the network scan and prioritize hosts by risk.
        Return ONLY valid JSON.
        Format:
        {{
            "host_ip": {{
                "priority": "alta|media|baja",
                "reason": "",
                "ports": []
            }}
        }}
        Data:
        {prepared_data}
    """

    try:
        response = client.responses.create(
            model="gpt-5.4-nano",
            input=prompt,
            temperature=0.3,
            max_output_tokens=1500
        )

        return response.output_text

    except Exception as e:
        print(f"[ERROR API] {e}")
        return None


def parse_response(response_text):
    """Convierte la respuesta de la IA en JSON usable."""

    if not response_text:
        return None

    try:
        data = json.loads(response_text)
        return data

    except json.JSONDecodeError:
        print("[ERROR] JSON inválido recibido")
        print(response_text)
        return None

def generate_html(data):
    """Genera un reporte HTML a partir del JSON."""

    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("template.html")

    html_output = template.render(data=data)

    with open("vulnerable_hosts.html", "w", encoding="utf-8") as f:
        f.write(html_output)

    print("[OK] Reporte generado: vulnerable_hosts.html")

if __name__ == "__main__":
    network = "192.168.138.0/24"

    # 1. Escaneo
    services = services_scan(network)

    # 2. Preparar datos
    prepared = prepare_data(services)

    # 3. IA
    response_text = prioritize_hosts(prepared)

    # 4. Parsear
    parsed_data = parse_response(response_text)

    # 5. HTML
    if parsed_data:
        generate_html(parsed_data)