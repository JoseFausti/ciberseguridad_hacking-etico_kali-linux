from file_exploiter import FileExploiter

if __name__ == "__main__":
    # Crear una instancia de FileExploiter para la red 10.0.2.15/24
    analyzer = FileExploiter('10.0.2.15/24')
    
    # Escanear la red para encontrar recursos de red activos
    smb_shares = analyzer.scan_smb_shares()
    
    # Imprimir los resultados del escaneo de manera amigable
    analyzer.pretty_print(smb_shares, data_type="shares")