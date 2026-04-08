import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
from scapy.all import *

# Desactivamos la salida de warnings por pantalla para Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkAnalyzer:
    """Analizador de red para identificar hosts, puertos y servicios abiertos en un rango de red dado.

    Attributes:
        network_range (str): Rango de red a analizar en formato CIDR.
        timeout (int): Tiempo máximo en segundos para esperar respuestas.
    """

    def __init__(self, network_range, timeout=1):
        """Inicializa la instancia del analizador de red con un rango de red y un tiempo de espera opcional.

        Args:
            network_range (str): Rango de la red a analizar.
            timeout (int, optional): Tiempo máximo en segundos para esperar respuestas. Default es 1.
        """
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        """Escanea un único host y puerto utilizando sockets para determinar si el puerto está abierto.

        Args:
            ip (str): Dirección IP del host a escanear.
            port (int): Puerto a escanear.

        Returns:
            tuple: Tupla que contiene el puerto y un booleano que indica si el puerto está abierto.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (port, True)
        except (socket.timeout, socket.error):
            return (port, False)

    def _scan_host_scapy(self, ip, scan_ports=(135, 445, 139)):
        """Utiliza Scapy para enviar paquetes SYN a puertos específicos y determinar si están abiertos.

        Args:
            ip (str): Dirección IP del host a escanear.
            scan_ports (tuple): Puertos a escanear.

        Returns:
            tuple: Tupla con la IP del host y un booleano que indica si al menos uno de los puertos está abierto.
        """
        for port in scan_ports:
            packet = IP(dst=ip) / TCP(dport=port, flags='S')
            answered, _ = sr(packet, timeout=self.timeout, verbose=0)
            if answered:
                return (ip, True)
        return (ip, False)

    def hosts_scan_arp(self):
        """Realiza un escaneo ARP para identificar hosts activos en la red.

        Returns:
            list: Lista de IPs de los hosts detectados que están activos.
        """
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = tqdm(srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0), desc="Escaneando con ARP")
        for _, received in answered:
            hosts_up.append(received.psrc)
        return hosts_up
    
    def ports_scan(self, port_range=(0, 10000)):
        """Escanea los puertos de los hosts activos dentro del rango especificado.

        Args:
            port_range (tuple): Rango de puertos a escanear.

        Returns:
            dict: Diccionario con IPs de hosts y la lista de puertos abiertos encontrados.
        """
        active_hosts = self.hosts_scan()
        all_open_ports = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            for ip in active_hosts:
                futures = []
                for port in tqdm(range(*port_range), desc=f"Escaneando puertos en {ip}"):
                    future = executor.submit(self._scan_host_sockets, ip, port)
                    futures.append(future)
                open_ports = [future.result()[0] for future in futures if future.result()[1]]
                if open_ports:
                    all_open_ports[ip] = open_ports
        return all_open_ports

    def hosts_scan(self, scan_ports=(135, 445, 139)):
        """Escanea la red para identificar hosts activos utilizando Scapy.

        Args:
            scan_ports (tuple): Puertos a escanear para determinar la actividad del host.

        Returns:
            list: Lista de IPs de los hosts activos detectados.
        """
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._scan_host_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(), desc="Escaneando hosts")}
            for future in tqdm(futures, desc="Obteniendo resultados"):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])
        return hosts_up
    
    def get_banner(self, ip, port):
        """Intenta obtener el banner de un servicio enviando una solicitud simple y leyendo la respuesta.

        Args:
            ip (str): Dirección IP del servicio.
            port (int): Puerto del servicio.

        Returns:
            str: Banner obtenido o mensaje de error si la conexión falla.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                s.send(b'Hello\r\n')
                return s.recv(1024).decode().strip()
        except Exception as e:
            return str(e)
    
    def services_scan(self, port_range=(0, 10000)):
        """Escanea servicios activos en los hosts detectados, intentando obtener banners de servicios en puertos abiertos.

        Args:
            port_range (tuple): Rango de puertos a escanear para la obtención de banners.

        Returns:
            dict: Diccionario que contiene información sobre los servicios activos detectados.
        """
        active_hosts = self.hosts_scan()
        services_info = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            for ip in active_hosts:
                futures = []
                services_info[ip] = {}
                for port in tqdm(range(*port_range), desc=f"Obteniendo banners en {ip}"):
                    future = executor.submit(self.get_banner, ip, port)
                    futures.append((future, port))
                for future, port in futures:
                    result = future.result()
                    if result and 'timed out' not in result and 'refused' not in result and 'No route to host' not in result:
                        services_info[ip][port] = result
        return services_info

    def pretty_print(self, data, data_type="hosts"):
        """Imprime de manera amigable los datos recolectados durante el escaneo.

        Args:
            data (list|dict): Datos a imprimir, dependiendo del tipo.
            data_type (str): Tipo de datos ('hosts', 'ports', 'services').
        """
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        
        if data_type == "hosts":
            table.add_column("Hosts Up", style="bold green")
            for host in data:
                table.add_row(host, end_section=True)
        
        elif data_type == "ports":
            table.add_column("IP Address", style="bold green")
            table.add_column("Open Ports", style="bold blue")
            for ip, ports in data.items():
                ports_str = ', '.join(map(str, ports))
                table.add_row(ip, ports_str, end_section=True)
        
        elif data_type == "services":
            table.add_column("IP Address", style="bold green")
            table.add_column("Port", style="bold blue")
            table.add_column("Service", style="bold yellow")
            for ip, services in data.items():
                for port, service in services.items():
                    table.add_row(ip, str(port), service, end_section=True)
        
        console.print(table)