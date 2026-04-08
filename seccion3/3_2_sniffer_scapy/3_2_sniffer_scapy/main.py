from sniffer_scapy import SnifferScapy

def main():
    # Instanciación del objeto SnifferScapy
    sniffer = SnifferScapy()

    # Lectura de un archivo de captura de paquetes
    sniffer.read_capture("wireshark_capture.pcapng")

    # Filtrado de paquetes que contienen el texto '443'
    packets = sniffer.filter_by_text('443')

    # Exportación de los paquetes filtrados a un nuevo archivo pcap
    sniffer.export_to_pcap(packets, "wireshark_capture_filtered.pcap")


if __name__ == "__main__":
    main()