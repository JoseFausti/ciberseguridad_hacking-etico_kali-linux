from sniffer_tshark import SnifferTshark

if __name__ == "__main__":
    # Crear una instancia de la clase SnifferTshark.
    sniffer = SnifferTshark()

    # Leer paquetes desde un archivo pcap especificado.
    sniffer.read_capture("captura_wireshark.pcapng")

    # Filtrar los paquetes que contienen la palabra 'phrack'.
    packets = sniffer.filter_by_text('phrack')

    # Exportar los paquetes filtrados a un nuevo archivo pcap.
    sniffer.export_to_pcap(packets, 'test.pcap')
