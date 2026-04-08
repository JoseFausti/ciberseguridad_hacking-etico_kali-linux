from network_analyzer import NetworkAnalyzer

if __name__ == "__main__":
    # Crear una instancia de NetworkAnalyzer para la red 192.168.138.0/24
    analyzer = NetworkAnalyzer('192.168.138.0/24')
    
    # Escanear la red para encontrar recursos de red activos
    smb_shares = analyzer.scan_smb_shares()
    
    # Imprimir los resultados del escaneo de manera amigable
    analyzer.pretty_print(smb_shares, data_type="shares")