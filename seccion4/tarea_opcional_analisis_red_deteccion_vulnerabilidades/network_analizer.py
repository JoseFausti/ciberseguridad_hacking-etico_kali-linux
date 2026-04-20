import ipaddress
import socket
from scapy.all import ARP, Ether, IP, TCP, sr, srp
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import re
from rich.console import Console
from rich.table import Table

class NetworkAnalyzer:
    """Analizador de red para identificar hosts, puertos y servicios abiertos en un rango de red dado.

    Atrtibutes:
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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect((ip, port))
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
        answered, _ = srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0)
        for _, received in answered:
            hosts_up.append(received.psrc)
        return hosts_up
    
    def hosts_scan(self, scan_ports=(135, 445, 139)):
        """Escanea la red para identificar hosts activos utilizando Scapy.

        Args:
            scan_ports (tuple): Puertos a escanear para determinar la actividad del host.

        Returns:
            list: Lista de IPs de los hosts activos detectados.
        """
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._scan_host_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(), desc="Escaneando hosts")}
            for future in tqdm(futures, desc="Obteniendo resultados"):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])
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
        with ThreadPoolExecutor(max_workers=20) as executor:
            for ip in active_hosts:
                futures = []
                for port in tqdm(range(*port_range), desc=f"Escaneando puertos en {ip}"):
                    future = executor.submit(self._scan_host_sockets, ip, port)
                    futures.append(future)
                open_ports = [future.result()[0] for future in futures if future.result()[1]]
                if open_ports:
                    all_open_ports[ip] = open_ports
        return all_open_ports
    
    def get_banner(self, ip, port):
        """Intenta obtener el banner de un servicio enviando una solicitud simple y leyendo la respuesta.

        Args:
            ip (str): Dirección IP del servicio.
            port (int): Puerto del servicio.

        Returns:
            str: Banner obtenido o mensaje de error si la conexión falla.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(b'Hello\r\n')
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception as e:
            return str(e)
        
    def get_service_name(self, banner, port=None):
        """Extrae el nombre del servicio a partir del banner obtenido.

        Args:
            banner (str): Banner del servicio.
            port (int): Puerto del servicio.

        Returns:
            str: Nombre del servicio normalizado (ssh, ftp, http, etc.)
        """
        if not banner:
            return "unknown"

        banner = banner.lower().strip()

        patterns = {
            "https": (r"https", 443),
            "http": (r"http", 80),
            "ssh": (r"\bssh\b", 22),
            "ftp": (r"\bftp\b", 21),
            "smtp": (r"smtp", 25),
            "pop3": (r"pop3", 110),
            "imap": (r"imap", 143),
            "mysql": (r"mysql", 3306),
            "postgresql": (r"postgres", 5432),
            "smb": (r"smb|microsoft-ds|netbios", 445),
            "rdp": (r"rdp|remote desktop", 3389),
            "dns": (r"dns", 53),
            "telnet": (r"telnet", 23)
        }

        for service, pattern in patterns.items():
            if re.search(pattern[0], banner):
                return service
        if port:
            for service, pattern in patterns.items():
                if pattern[1] == port:
                    return service

        return "unknown"
        
    def services_scan(self, port_range=(0, 10000)):
        """Escanea servicios activos en los hosts detectados, intentando obtener banners de servicios en puertos abiertos.

        Args:
            port_range (tuple): Rango de puertos a escanear para la obtención de banners.

        Returns:
            dict: Diccionario que contiene información sobre los servicios activos detectados.
        """
        active_hosts = self.hosts_scan()
        services_info = {}
        with ThreadPoolExecutor(max_workers=20) as executor:
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
    
    def analyze_services(self, port_range=(0, 10000)):
        """Escanea la red y devuelve servicios normalizados por IP y puerto."""

        services = self.services_scan(port_range)
        normalized = {}

        for ip, ports in services.items():
            normalized[ip] = {}

            for port, banner in ports.items():
                service = self.get_service_name(banner, port)

                if service == "unknown":
                    continue

                normalized[ip][port] = service

            # Eliminar IPs sin servicios útiles
            if not normalized[ip]:
                del normalized[ip]

        return normalized
    
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