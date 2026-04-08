import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
from scapy.all import *

# Configuración inicial para desactivar advertencias de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkAnalyzer:
    """Clase para realizar análisis de redes mediante ARP y escaneo de puertos TCP.

    Attributes:
        network_range (str): Rango de direcciones IP para analizar.
        timeout (int): Tiempo máximo en segundos para esperar respuestas.
    """

    def __init__(self, network_range, timeout=1):
        """Inicializa el analizador de red con el rango de red y el timeout especificado.

        Args:
            network_range (str): Rango de direcciones IP en formato CIDR.
            timeout (int): Timeout en segundos para las operaciones de red.
        """
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        """Realiza un escaneo de un puerto específico usando sockets.

        Args:
            ip (str): Dirección IP del host a escanear.
            port (int): Puerto a escanear.

        Returns:
            tuple: Tupla con el puerto y un booleano indicando si está abierto.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (port, True)
        except (socket.timeout, socket.error):
            return (port, False)
        
    def _scan_host_scapy(self, ip, scan_ports=(135, 445, 139)):
        """Realiza un escaneo de puertos usando Scapy para construir paquetes TCP.

        Args:
            ip (str): Dirección IP del host a escanear.
            scan_ports (tuple): Puertos a escanear.

        Returns:
            tuple: Tupla con la IP y un booleano indicando si alguno de los puertos está abierto.
        """
        for port in scan_ports:
            packet = IP(dst=ip)/TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
            answered, _ = sr(packet, timeout=self.timeout, verbose=0)
            if answered:
                return (ip, True)
        return (ip, False)
    
    def hosts_scan_arp(self):
        """Escanea la red para encontrar hosts activos usando ARP.

        Returns:
            list: Lista de direcciones IP de los hosts detectados.
        """
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = tqdm(srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0), desc="Escaneando con ARP")
        for _, received in answered:
            hosts_up.append(received.psrc)
        return hosts_up
    
    def ports_scan(self, port_range=(0, 10000)):
        """Escanea los puertos de los hosts activos en el rango especificado.

        Args:
            port_range (tuple): Rango de puertos a escanear.

        Returns:
            dict: Diccionario con las IPs y sus puertos abiertos.
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
        """Escanea la red para identificar hosts activos que responden a paquetes TCP específicos.

        Args:
            scan_ports (tuple): Puertos específicos para el escaneo TCP.

        Returns:
            list: Lista de direcciones IP de los hosts activos.
        """
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._scan_host_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(), desc="Escaneando hosts")}
            for future in tqdm(futures, desc="Obteniendo resultados"):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])
        return hosts_up

    def pretty_print(self, data, data_type="hosts"):
        """Imprime los resultados del escaneo de manera estructurada y estilizada.

        Args:
            data (list | dict): Datos de los hosts o puertos a imprimir.
            data_type (str): Tipo de datos a imprimir ('hosts' o 'ports').
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

        console.print(table)