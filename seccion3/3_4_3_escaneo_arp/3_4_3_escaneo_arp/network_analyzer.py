import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
from scapy.all import *
import logging

# Desactivamos la salida de warnings por pantalla de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkAnalyzer:
    """Esta clase proporciona métodos para detectar hosts activos en una red usando
    ARP y TCP/IP scans.

    Attributes:
        network_range (str): Rango de la red a analizar.
        timeout (int): Tiempo máximo de espera para las respuestas de los hosts en segundos.
    """
    
    def __init__(self, network_range, timeout=1):
        """Inicializa la instancia de NetworkAnalyzer.

        Args:
            network_range (str): Rango de red en notación CIDR (por ejemplo, '192.168.1.0/24').
            timeout (int): Tiempo en segundos para esperar respuesta de un host.
        """
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        """Escanea un host específico utilizando sockets.

        Args:
            ip (str): Dirección IP del host a escanear.
            port (int): Puerto TCP a utilizar para el escaneo.

        Returns:
            tuple: Tupla conteniendo la IP del host y un booleano indicando si está activo.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (ip, True)
        except (socket.timeout, socket.error):
            return (ip, False)
        
    def _scan_host_scapy(self, ip, scan_ports=(135, 445, 139)):
        """Realiza un escaneo de puertos utilizando Scapy.

        Args:
            ip (str): Dirección IP del host a escanear.
            scan_ports (list): Puertos a escanear.

        Returns:
            tuple: Tupla conteniendo la IP del host y un booleano indicando si algún puerto está abierto.
        """
        for port in scan_ports:
            packet = IP(dst=ip)/TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
            answered, _ = sr(packet, timeout=self.timeout, verbose=0)
            if answered:
                return (ip, True)
        return (ip, False)
    
    def hosts_scan_arp(self):
        """Escanea la red usando ARP para identificar hosts activos.

        Returns:
            list: Lista de IPs de los hosts activos detectados.
        """
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = tqdm(srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0), desc="Escaneando con ARP")
        for _, received in answered:
            hosts_up.append(received.psrc)
        return hosts_up
        
    def hosts_scan(self, scan_ports=(135, 445, 139)):
        """Realiza un escaneo de red utilizando Scapy para detectar puertos abiertos en los hosts.

        Args:
            scan_ports (tuple): Puertos a escanear.

        Returns:
            list: Lista de IPs de los hosts activos con puertos abiertos.
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
        """Imprime los datos de manera estructurada y estilizada en la consola.

        Args:
            data (list): Datos a imprimir.
            data_type (str): Tipo de datos, puede ser 'hosts' para listar los hosts activos.
        """
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        if data_type == "hosts":
            table.add_column("Hosts Up", style="bold green")
            for host in data:
                table.add_row(host, end_section=True)
        console.print(table)