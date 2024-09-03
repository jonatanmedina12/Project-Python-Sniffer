# Sniffer de Red para Windows

Este proyecto implementa dos sniffers de red para Windows: uno utilizando Scapy y otro utilizando pyshark (una interfaz de Python para tshark). Permite capturar paquetes de red, filtrarlos y analizarlos.

## Requisitos
- Python 3.7+
- Scapy
- pyshark
- Npcap (https://npcap.com/)
- Wireshark (https://www.wireshark.org/)
- pip install -r .\requirements.txt
## Instalación
1. Instala Python desde https://www.python.org/downloads/
2. Instala Npcap desde https://npcap.com/
3. Instala Wireshark desde https://www.wireshark.org/
4. Instala las bibliotecas necesarias:
5. El script iniciará la captura en la interfaz Ethernet por defecto.

## Funcionalidades

### Sniffer Scapy
- Listar interfaces de red disponibles
- Capturar paquetes en una interfaz específica
- Filtrar paquetes por protocolo o contenido
- Exportar paquetes capturados a archivos PCAP
- Mostrar detalles de los paquetes capturados

### Sniffer Tshark
- Capturar paquetes en múltiples interfaces
- Mostrar resumen de paquetes en tiempo real
- Aplicar filtros de visualización

## Filtros y Búsqueda

### Filtros de Captura (BPF) para Scapy
- `tcp`: Solo paquetes TCP
- `udp`: Solo paquetes UDP
- `port 80`: Tráfico en el puerto 80
- `host 192.167.1.1`: Tráfico hacia o desde la IP 192.167.1.1

### Filtros de Visualización para Tshark
- `tcp`: Solo paquetes TCP
- `http`: Solo tráfico HTTP
- `ip.addr == 192.167.1.100`: Tráfico de una IP específica

### Filtrado Post-Captura en Scapy

1. Por Protocolo:
```
tcp_packets = sniffer.filter_by_protocol("TCP")
 ```
## Diferencias entre Scapy y Tshark

Scapy ofrece más flexibilidad y control sobre la manipulación de paquetes.
Tshark (a través de pyshark) proporciona una interfaz más sencilla y puede ser más rápido para capturas grandes.
Scapy es puramente Python, mientras que Tshark depende de la instalación de Wireshark.

## Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue para discutir cambios mayores antes de enviar un pull request.
# Filtros por protocolo:
 ```
tcp: Sólo paquetes TCP
udp: Sólo paquetes UDP
icmp: Sólo paquetes ICMP
http: Sólo tráfico HTTP
https: Sólo tráfico HTTPS
dns: Sólo tráfico DNS
ftp: Sólo tráfico FTP
ssh: Sólo tráfico SSH
telnet: Sólo tráfico Telnet
smtp: Sólo tráfico SMTP
pop: Sólo tráfico POP3
 ```

# Filtros por dirección IP:
 ```
ip.src == 192.167.1.100: Paquetes con dirección IP de origen específica
ip.dst == 10.0.0.1: Paquetes con dirección IP de destino específica
ip.addr == 172.16.0.5: Paquetes con dirección IP de origen o destino específica
 ```

# Filtros por puerto:
 ```
tcp.port == 80: Tráfico en el puerto TCP 80
udp.port == 53: Tráfico en el puerto UDP 53
tcp.srcport == 443: Tráfico desde el puerto de origen TCP 443
tcp.dstport == 22: Tráfico hacia el puerto de destino TCP 22
 ```

# Filtros combinados:
 ```
http or https: Tráfico HTTP o HTTPS
tcp.port == 80 or tcp.port == 443: Tráfico en puertos web comunes
ip.src == 192.167.1.100 and tcp.dstport == 443: Tráfico HTTPS desde una IP específica
 ```

# Filtros por contenido:
 ```
http.request.method == "GET": Solicitudes HTTP GET
http.request.method == "POST": Solicitudes HTTP POST
http.host contains "example.com": Tráfico HTTP hacia un dominio específico
dns.qry.name contains "google": Consultas DNS que contienen "google"
 ```

# Filtros por tamaño de paquete:
 ```
frame.len > 1000: Paquetes mayores de 1000 bytes
frame.len < 128: Paquetes menores de 128 bytes
 ```

# Filtros por flags TCP:
 ```
tcp.flags.syn == 1: Paquetes SYN
tcp.flags.ack == 1: Paquetes ACK
tcp.flags.fin == 1: Paquetes FIN
 ```

# Filtros por MAC address:
 ```
eth.src == 00:11:22:33:44:55: Paquetes con una dirección MAC de origen específica
eth.dst == AA:BB:CC:DD:EE:FF: Paquetes con una dirección MAC de destino específica
 ```

# Filtros para excluir tráfico:
 ```
!dns: Excluir tráfico DNS
!(arp or icmp): Excluir tráfico ARP e ICMP
 ```

# Filtros más avanzados:
 ```
(ip.src == 192.167.1.100 and ip.dst == 10.0.0.1) or (ip.src == 10.0.0.1 and ip.dst == 192.167.1.100): Tráfico entre dos IPs específicas en ambas direcciones
http.request.uri contains "login": Solicitudes HTTP que contienen "login" en la URI
tcp.analysis.retransmission: Paquetes TCP retransmitidos
 ```
## Nota de Seguridad
Este conjunto de herramientas está diseñado para fines educativos y de investigación. Asegúrate de usar estas herramientas de manera responsable y en cumplimiento con las leyes y regulaciones aplicables. Algunos usos pueden requerir autorización adecuada.
## Licencia
Mozilla Public License Version 2.0
