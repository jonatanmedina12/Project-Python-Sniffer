from src.controller.sniffer_tshark_controller import SnifferTshark

from src.controller.sniffer_scapy_controller import SnifferScapy

def execution():
    sniffer = SnifferTshark()
    # Puedes ajustar el filtro y el número de paquetes según tus necesidades
    #tcp,udp,icmp,http,https,dns,ftp,ssh,telnet,smtp,pop
    #ip.src == 192.167.1.100: Paquetes con dirección IP de origen específica
    #ip.dst == 10.0.0.1: Paquetes con dirección IP de destino específica
    #ip.addr == 172.16.0.5: Paquetes con dirección IP de origen o destino específica

    sniffer.start_capture(display_filter="ssh", packet_count=50)

def list_interfaces():
    from scapy.arch.windows import get_windows_if_list
    interfaces = get_windows_if_list()
    for interface in interfaces:
        print(f"Nombre: {interface['name']}")
        print(f"Descripción: {interface['description']}")
        print(f"MAC: {interface.get('mac', 'N/A')}")
        print(f"IPv4: {interface.get('ips', ['N/A'])}")
        print("-" * 50)

def execution_scapy():
    sniffer = SnifferScapy()

    print("Interfaces de red disponibles:")
    list_interfaces()

    interface = input("Ingrese el nombre de la interfaz que desea usar (por defecto 'Ethernet'): ") or "Ethernet"
    filter_str = input("Ingrese el filtro de captura (por defecto 'tcp'): ") or "tcp"
    count = int(input("Ingrese el número de paquetes a capturar (0 para capturar indefinidamente): ") or "100")

    sniffer.start_capture(interface=interface, filter=filter_str, count=count)

    # Exportar todos los paquetes capturados
    sniffer.export_to_pcap(sniffer.captured_packets, "captura_completa.pcap")

    # Filtrar paquetes HTTP y exportarlos
    http_packets = sniffer.filter_by_text("HTTP")
    if http_packets:
        sniffer.export_to_pcap(http_packets, "captura_http.pcap")
        print("Detalles de los paquetes HTTP capturados:")
        sniffer.print_packet_details(http_packets)
    else:
        print("No se capturaron paquetes HTTP.")