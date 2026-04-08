import nmap

def hosts_scan(network):
    """ Realiza un escaneo de hosts activos dentro de una red específica utilizando nmap.

    Args:
        network (str): La red a escanear, especificada en notación CIDR (ej. '192.168.1.0/24').

    Returns:
        list: Una lista de direcciones IP de los hosts que están activos en la red.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts

def services_scan(network):
    """ Realiza un escaneo de los servicios en los hosts activos de una red especificada.

    Args:
        network (str): La red a escanear, en notación CIDR.

    Returns:
        dict: Un diccionario donde cada clave es una dirección IP de un host activo
              y cada valor es otro diccionario que describe los protocolos y los
              puertos abiertos, junto con el servicio y la versión de dicho servicio
              que se está ejecutando en cada puerto.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sV')
    network_data = {}
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            network_data[host] = {}
            for proto in nm[host].all_protocols():
                network_data[host][proto] = {}
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['product'] + " " + nm[host][proto][port]['version']
                    network_data[host][proto][port] = {'service': service, 'version': version}
    return network_data


if __name__ == "__main__":
    # Ejemplo de uso de las funciones para escanear hosts y servicios en una red.
    services_up = services_scan('192.168.138.0/24')
    print(services_up)