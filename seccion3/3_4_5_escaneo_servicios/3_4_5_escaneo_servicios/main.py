from network_analyzer import NetworkAnalyzer

if __name__ == "__main__":
    # Crear una instancia de NetworkAnalyzer para la red 192.168.138.0/24
    analyzer = NetworkAnalyzer('192.168.138.0/24')
    
    # Escanear la red para encontrar servicios que están activos
    services = analyzer.services_scan()
    
    # Imprimir los resultados del escaneo de manera amigable
    analyzer.pretty_print(services, data_type="services")