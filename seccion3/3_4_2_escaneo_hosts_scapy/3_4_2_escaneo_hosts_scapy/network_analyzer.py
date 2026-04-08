import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
from scapy.all import *

# Configuración para desactivar los warnings de Scapy en el log
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkAnalyzer:
    """Análisis de red para identificar hosts activos dentro de un rango de IP especificado.

    Atributos:
        network_range (str): Rango de red en notación CIDR a analizar.
        timeout (int): Tiempo máximo en segundos para esperar respuesta de cada host.
    """
    
    def __init__(self, network_range, timeout=1):
        """Inicializa el analizador de red con el rango y el tiempo de espera especificados.

        Args:
            network_range (str): Rango de red en formato CIDR.
            timeout (int): Tiempo de espera para la respuesta de cada host, en segundos.
        """
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        """Escanea un host para determinar si un puerto específico está abierto, utilizando sockets.

        Args:
            ip (str): Dirección IP del host a escanear.
            port (int): Puerto a verificar en el host.

        Returns:
            tuple: Tupla conteniendo la IP del host y un booleano que indica si el puerto está abierto.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (ip, True)
        except (socket.timeout, socket.error):
            return (ip, False)
        
    def _scan_host_scapy(self, ip, scan_ports=(135, 445, 139)):
        """Utiliza Scapy para escanear puertos específicos de un host utilizando paquetes TCP SYN.

        Args:
            ip (str): Dirección IP del host a escanear.
            scan_ports (tuple): Puertos a escanear en el host.

        Returns:
            tuple: Tupla conteniendo la IP del host y un booleano que indica si alguno de los puertos está abierto.
        """
        for port in scan_ports:
            packet = IP(dst=ip)/TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
            answered, _ = sr(packet, timeout=self.timeout, verbose=0)
            if answered:
                return (ip, True)
        return (ip, False)
        
    def hosts_scan(self, scan_ports=(135, 445, 139)):
        """Realiza un escaneo sobre todos los hosts en el rango de red especificado.

        Args:
            scan_ports (tuple): Puertos a escanear en cada host.

        Returns:
            list: Lista de IPs de los hosts que están activos.
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
        """Imprime los datos de manera elegante en una tabla.

        Args:
            data (list): Datos a imprimir.
            data_type (str): Tipo de datos para adecuar la impresión.
        """
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        if data_type == "hosts":
            table.add_column("Hosts Up", style="bold green")
            for host in data:
                table.add_row(host, end_section=True)
        console.print(table)