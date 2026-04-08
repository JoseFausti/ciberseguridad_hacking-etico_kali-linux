def verificar_disponibilidad(hosts: list[str]):
    resultados = {}
    for item in hosts:
        if item[0:3] == '192':
            resultados = {**resultados, **{item: 'Disponible'}} # Concatenar diccionarios: equivalente al spread operator de JS
        else:
            resultados.update({item: 'No Disponible'})
    return resultados