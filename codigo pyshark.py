import pyshark

def find_most_prevalent_protocol(pcap_file):
    # Carga la traza pcap
    cap = pyshark.FileCapture(pcap_file)

    # Diccionario para contar ocurrencias de cada protocolo
    protocol_counts = {}

    # Analiza cada paquete
    for packet in cap:
        # Obtiene el protocolo de más alto nivel en el paquete
        try:
            highest_layer = packet.highest_layer
            # Actualiza el conteo de protocolos
            protocol_counts[highest_layer] = protocol_counts.get(highest_layer, 0) + 1
        except AttributeError:
            # Si hay un error al obtener la capa, simplemente continúa con el siguiente paquete
            continue

    # Encuentra el protocolo con el mayor número de ocurrencias
    most_prevalent_protocol = max(protocol_counts, key=protocol_counts.get)

    # Retorna el protocolo más prevalente y su conteo
    return most_prevalent_protocol, protocol_counts[most_prevalent_protocol]

# Usar la función con el archivo pcap deseado
most_prevalent_protocol, count = find_most_prevalent_protocol('trace_1.pcap')
print(f"El protocolo de aplicación más prevalente es: {most_prevalent_protocol} con {count} paquetes.")
