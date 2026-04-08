from network_analyzer import NetworkAnalyzer

if __name__ == "__main__":
    # Crear una instancia de NetworkAnalyzer para la red 192.168.138.0/24
    analyzer = NetworkAnalyzer('192.168.138.0/24')
    
    # Escanear la red para encontrar hosts que están activos
    ports_up = analyzer.ports_scan(port_range=(8065, 8070))
    
    # Imprimir los resultados del escaneo de manera amigable
    analyzer.pretty_print(ports_up, data_type="ports")