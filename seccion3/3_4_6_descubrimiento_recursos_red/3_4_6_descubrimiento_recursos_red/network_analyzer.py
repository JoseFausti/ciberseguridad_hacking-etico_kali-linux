import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
from scapy.all import *
from smb.SMBConnection import SMBConnection

# Desactivamos la salida de warnings por pantalla para Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkAnalyzer:
    """Clase para analizar redes a través de diferentes técnicas de escaneo.

    Atributos:
        network_range (str): Rango de direcciones IP a analizar.
        timeout (int): Tiempo máximo de espera para las conexiones en segundos.
    """

    def __init__(self, network_range, timeout=1):
        """Inicializa el analizador de red con un rango de red y un tiempo de espera."""
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        """Intenta conectar a un puerto de un host utilizando un socket.

        Args:
            ip (str): Dirección IP del host a escanear.
            port (int): Puerto a escanear.

        Returns:
            tuple: Tupla (puerto, estado) donde estado es True si el puerto está abierto.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (port, True)
        except (socket.timeout, socket.error):
            return (port, False)
        
    def _scan_host_scapy(self, ip, scan_ports=(135, 445, 139)):
        """Utiliza Scapy para enviar un paquete TCP a múltiples puertos y detecta respuestas.

        Args:
            ip (str): Dirección IP del host a escanear.
            scan_ports (tuple): Puertos a escanear.

        Returns:
            tuple: Tupla (ip, estado) donde estado es True si al menos un puerto está abierto.
        """
        for port in scan_ports:
            packet = IP(dst=ip)/TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
            answered, _ = sr(packet, timeout=self.timeout, verbose=0)
            if answered:
                return (ip, True)
        return (ip, False)

    def hosts_scan_arp(self):
        """Realiza un escaneo ARP para identificar hosts activos en la red.

        Returns:
            list: Lista de direcciones IP de los hosts activos.
        """
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = tqdm(srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0), desc="Escaneando con ARP")
        for _, received in answered:
            hosts_up.append(received.psrc)
        return hosts_up

    def ports_scan(self, port_range=(0, 10000)):
        """Escanea los puertos de los hosts descubiertos en el rango especificado.

        Args:
            port_range (tuple): Rango de puertos a escanear.

        Returns:
            dict: Diccionario de hosts y sus puertos abiertos.
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
        """Realiza un escaneo de hosts activos utilizando técnicas avanzadas de Scapy.

        Args:
            scan_ports (tuple): Puertos a utilizar para detectar la actividad del host.

        Returns:
            list: Lista de direcciones IP de hosts activos.
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
        """Obtiene el banner de un servicio corriendo en un puerto específico de un host.

        Args:
            ip (str): Dirección IP del host.
            port (int): Puerto del servicio.

        Returns:
            str: Banner del servicio o mensaje de error.
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
        """Escanea y detecta servicios en los puertos especificados de los hosts activos.

        Args:
            port_range (tuple): Rango de puertos a escanear.

        Returns:
            dict: Diccionario de hosts con información detallada de los servicios detectados.
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

    def discover_public_shares(self, ip):
        """Descubre y enumera los recursos compartidos SMB públicos en un host específico.

        Args:
            ip (str): Dirección IP del host a examinar.

        Returns:
            tuple: Tupla de la IP del host y un diccionario con los detalles de los recursos compartidos.
        """
        user_name = ""
        password = ""
        local_machine_name = "laptop"
        server_machine_name = ip

        share_details = {}
        try:
            conn = SMBConnection(user_name, password, local_machine_name, server_machine_name, use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(ip, 445, timeout=self.timeout):
                print(f"Conectado a {ip}")
                for share in conn.listShares(timeout=10):
                    if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                        try:
                            files = conn.listPath(share.name, '/')
                            share_details[share.name] = [file.filename for file in files if file.filename not in ['.', '..']]
                        except Exception as e:
                            print(f"No se ha podido acceder a {share.name} en {ip}: {e}")
                conn.close()
        except Exception as e:
            print(f"No se han podido obtener los recursos de {ip}: {e}")
        return ip, share_details

    def scan_smb_shares(self):
        """Realiza un escaneo de recursos compartidos SMB en todos los hosts activos detectados.

        Returns:
            dict: Diccionario con los hosts y sus recursos compartidos SMB descubiertos.
        """
        active_hosts = self.hosts_scan()
        all_shares = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.discover_public_shares, ip): ip for ip in tqdm(active_hosts, desc="Discovering SMB Shares")}
            for future in tqdm(futures, desc="Obteniendo recursos compartidos"):
                ip, shares = future.result()
                if shares:
                    all_shares[ip] = shares
        return all_shares

    def pretty_print(self, data, data_type="hosts"):
        """Imprime los datos recogidos durante los escaneos de manera amigable y estructurada.

        Args:
            data (dict or list): Datos a imprimir.
            data_type (str): Tipo de datos ('hosts', 'ports', 'services', 'shares').

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
        
        if data_type == "shares":
            for ip, shares in data.items():
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("IP Address", style="bold green")
                table.add_column("Shared Folder", style="bold blue")
                table.add_column("Files", style="bold yellow")
                for share, files in shares.items():
                    files_str = ', '.join(files)
                    table.add_row(ip, share, files_str, end_section=True)
        console.print(table)