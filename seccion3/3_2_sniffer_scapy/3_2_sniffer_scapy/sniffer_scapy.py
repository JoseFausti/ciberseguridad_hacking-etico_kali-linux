from scapy.all import sniff, PcapReader, wrpcap

class SnifferScapy:
    """Clase para capturar, leer y filtrar paquetes de red utilizando Scapy.

    Atributos:
        captured_packets (list): Lista para almacenar los paquetes capturados.
    """

    def __init__(self):
        """Inicializa la instancia de SnifferScapy."""
        self.captured_packets = []

    def start_capture(self, interface="eth0", filter=""):
        """Inicia la captura de paquetes de red. Se ejecuta hasta que se interrumpe manualmente con Ctrl+C.

        Args:
            interface (str): Nombre de la interfaz de red a monitorizar. Por defecto es 'eth0'.
            filter (str): Filtro de captura aplicado a los paquetes. Por defecto está vacío.
        """
        print("Captura de paquetes iniciada. Pulsa Ctrl+C para detenerla.")
        try:
            self.captured_packets = sniff(
                iface=interface,
                filter=filter,
                prn=lambda x: x.summary(),
                store=True
            )
        except KeyboardInterrupt:
            print(f"Captura finalizada. El número de paquetes capturados es: {len(self.captured_packets)}")

    def read_capture(self, pcapfile):
        """Lee paquetes desde un archivo .pcap.

        Args:
            pcapfile (str): Ruta del archivo .pcap a leer.
        """
        try:
            self.captured_packets = [pkt for pkt in PcapReader(pcapfile)]
            print(f"Lectura del fichero {pcapfile} realizada correctamente.")
        except Exception as e:
            print(f"Error al leer el fichero {pcapfile}: {e}")

    def filter_by_protocol(self, protocol):
        """Filtra los paquetes capturados por protocolo específico.

        Args:
            protocol (str): Nombre del protocolo por el cual filtrar.

        Returns:
            list: Lista de paquetes que contienen el protocolo especificado.
        """
        filtered_packets = [pkt for pkt in self.captured_packets if pkt.haslayer(protocol)]
        return filtered_packets
    
    def filter_by_text(self, text):
        """Filtra los paquetes capturados que contienen un texto específico en sus campos.

        Args:
            text (str): Texto a buscar en los campos de los paquetes.

        Returns:
            list: Lista de paquetes que contienen el texto especificado.
        """
        filtered_packets = []
        for pkt in self.captured_packets:
            found = False
            layer = pkt
            while layer:
                for field in layer.fields_desc:
                    field_name = field.name
                    field_value = layer.getfieldval(field_name)
                    if text in field_name or text in str(field_value):
                        filtered_packets.append(pkt)
                        found = True
                        break
                if found:
                    break
                layer = layer.payload
        return filtered_packets
    
    def print_packet_details(self, packets=None):
        """Imprime los detalles de los paquetes especificados.

        Args:
            packets (list, optional): Lista de paquetes cuyos detalles se imprimirán.
                Si no se especifica, se imprimirán los detalles de todos los paquetes capturados.
        """
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            packet.show()
            print("---" * 20)

    def export_to_pcap(self, packets, filename="capture.pcap"):
        """Exporta paquetes a un archivo .pcap.

        Args:
            packets (list): Lista de paquetes a exportar.
            filename (str): Nombre del archivo donde se guardarán los paquetes.
        """
        wrpcap(filename, packets)
        print("Paquetes guardados en disco satisfactoriamente.")