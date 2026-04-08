import pyshark
from scapy.all import wrpcap, Ether

class SnifferTshark:
    """Clase para capturar paquetes de red usando Tshark y Scapy.

    Atributos:
        capture (pyshark.Capture): Objeto para la captura de paquetes.
        captured_packets (list): Lista que almacena los paquetes capturados.
    """

    def __init__(self):
        """Inicializa la captura y la lista de paquetes capturados."""
        self.capture = None
        self.captured_packets = []

    def start_capture(self, interface="any", display_filter=""):
        """Inicia la captura de paquetes en tiempo real.

        Args:
            interface (str): Nombre de la interfaz de red donde capturar los paquetes.
            display_filter (str): Filtro de visualización para aplicar en la captura.
        """
        self.capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter,
            use_json=True,
            include_raw=True
        )
        try:
            print("[+] Captura de paquetes iniciada. Pulsa Ctrl+C para detenerla...")
            for packet in self.capture.sniff_continuously():
                self.captured_packets.append(packet)
        except (KeyboardInterrupt, EOFError):
            print(f"[+] Captura finalizada. Paquetes capturados: {len(self.captured_packets)}.")

    def read_capture(self, pcapfile, display_filter=""):
        """Lee paquetes de un archivo pcap especificado.

        Args:
            pcapfile (str): Ruta al archivo pcap para leer los paquetes.
            display_filter (str): Filtro de visualización para aplicar durante la lectura.
        """
        try:
            self.capture = pyshark.FileCapture(
                input_file=pcapfile,
                display_filter=display_filter,
                keep_packets=False,
                use_json=True, # Comenta esta linea si vas a utilizar 'print_packet_detail'
                include_raw=True # Comenta esta linea si vas a utilizar 'print_packet_detail'
            )
            self.captured_packets = [pkt for pkt in self.capture]
            print(f"Lectura de {pcapfile} realizada correctamente.")
        except Exception as e:
            print(f"Error al leer el fichero {pcapfile}: {e}")

    def filter_by_protocol(self, protocol):
        """Filtra los paquetes capturados por protocolo.

        Args:
            protocol (str): Nombre del protocolo por el cual filtrar.

        Returns:
            list: Lista de paquetes filtrados que contienen el protocolo especificado.
        """
        filtered_packets = [pkt for pkt in self.captured_packets if protocol in pkt]
        return filtered_packets
    
    def filter_by_text(self, text):
        """Filtra los paquetes capturados que contienen un texto específico.

        Args:
            text (str): Texto a buscar dentro de los paquetes.

        Returns:
            list: Lista de paquetes que contienen el texto especificado.
        """
        filtered_packets = []
        for pkt in self.captured_packets:
            for layer in pkt.layers:
                for field_line in layer._get_all_field_lines():
                    if text in field_line:
                        filtered_packets.append(pkt)
                        break
        return filtered_packets
                    
    def export_to_pcap(self, packets, filename='capture.pcap'):
        """Exporta una lista de paquetes a un archivo pcap.

        Args:
            packets (list): Lista de paquetes a exportar.
            filename (str): Nombre del archivo de salida.
        """
        scapy_packets = [Ether(pkt.get_raw_packet()) for pkt in packets]
        wrpcap(filename, scapy_packets)
        print(f"[+] Paquetes guardados en {filename}")

    def print_packet_detail(self, packets=None):
        """Imprime los detalles de los paquetes especificados.

        Args:
            packets (list, optional): Lista de paquetes a imprimir. Si es None, se imprimen todos los capturados.
        """
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            print(packet)
            print("---"*20)