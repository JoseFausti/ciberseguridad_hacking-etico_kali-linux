from vulnerability_scanner import VulnerabilityScanner


if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    servicio = "ProFTPD 1.3.5"
    cves_encontrados = scanner.search_cves(servicio)
    scanner.pretty_print(cves_encontrados)