import dns.resolver

def resolve_dns_records(domain, record_types):
    """
    Resuelve y muestra los registros DNS para un dominio específico y tipos de registro.

    Args:
        domain (str): El dominio para el cual resolver los registros DNS.
        record_types (list): Lista de tipos de registros DNS a resolver.
    """
    # Crea una instancia de Resolver para consultar los servidores DNS
    resolver = dns.resolver.Resolver()

    # Itera sobre los tipos de registro proporcionados
    for record_type in record_types:
        try:
            # Intenta resolver el registro actual
            answers = resolver.resolve(domain, record_type)
        except dns.resolver.NoAnswer:
            # Continua con el siguiente tipo de registro si no hay respuesta
            continue

        # Imprime los resultados de los registros DNS obtenidos
        print(f"{record_type} registros para {domain}:")
        for data in answers:
            print(f" {data}")


if __name__ == "__main__":
    # Definición de variables para el dominio objetivo y los tipos de registros a consultar
    target_domain = "udemy.com"
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

    # Llama a la función con los parámetros definidos
    resolve_dns_records(target_domain, record_types)