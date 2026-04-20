from network_analizer import NetworkAnalyzer
from vulnerability_scanner import VulnerabilityScanner

if __name__ == "__main__":
    # Crear instancia del analizador de red y escáner de vulnerabilidades
    network_analyzer = NetworkAnalyzer("192.168.1.103/24")
    vulnerability_scanner = VulnerabilityScanner()

    # Obtener servicios activos en la red normalizados
    services_data = network_analyzer.analyze_services()
   
    # Extraer servicios únicos para escanear vulnerabilidades
    services_list = [service for ports in services_data.values() for service in ports.values()]

    # Escanear vulnerabilidades para los servicios detectados
    vulnerabilities = vulnerability_scanner.search_multiple_services(services_list)

    # Generar informe de vulnerabilidades para cada servicio detectado
    results = []
    for ip, ports in services_data.items():
        for port, service in ports.items():
            results.append({
                "ip": ip,
                "port": port,
                "service": service,
                "cves": vulnerabilities.get(service, [])
            })

    # Imprimir resultados
    vulnerability_scanner.pretty_print_full(results)