import pyshark
from datetime import datetime


class SnifferTshark:
    def __init__(self):
        self.captures = []
        self.captured_packets = []

    def start_capture(self, interfaces=None, display_filter="", packet_count=100):
        if interfaces is None:
            interfaces = ["Ethernet"]  # Puedes ajustar esto según tus necesidades

        for interface in interfaces:
            try:
                capture = pyshark.LiveCapture(
                    interface=interface,
                    display_filter=display_filter,
                    use_json=True,
                    include_raw=True
                )
                self.captures.append(capture)
                print(f"[+] Captura iniciada en la interfaz: {interface}")
            except Exception as e:
                print(f"[-] No se pudo iniciar la captura en la interfaz {interface}: {str(e)}")

        if not self.captures:
            print("[-] No se pudo iniciar la captura en ninguna interfaz.")
            return

        try:
            print("[+] Captura de paquetes iniciada. Pulsa Ctrl+C para detenerla.")
            for capture in self.captures:
                for packet in capture.sniff_continuously(packet_count=packet_count):
                    self.captured_packets.append(packet)
                    self.print_packet_summary(packet)
        except KeyboardInterrupt:
            print(f"[+] Captura finalizada. Paquetes capturados: {len(self.captured_packets)}")

    @staticmethod
    def print_packet_summary(packet):
        try:
            timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else packet.highest_layer
            src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            length = packet.length

            print(f"{timestamp} | {protocol:8} | {src_ip:15} -> {dst_ip:15} | Length: {length}")
        except AttributeError:
            print(f"Paquete no compatible: {packet}")

    def print_packet_detail(self, packets=None):
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            self.print_packet_summary(packet)