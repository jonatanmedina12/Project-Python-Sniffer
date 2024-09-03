import os
from scapy.all import sniff, wrpcap
from typing import List, Optional

from scapy.packet import Packet


class SnifferScapy:
    def __init__(self):
        self.captured_packets: List[Packet] = []

    def start_capture(self, interface: str = "Ethernet", filter: str = "", count: int = 0) -> None:
        print(f"Iniciando captura en la interfaz: {interface}")
        try:
            self.captured_packets = sniff(iface=interface, filter=filter,
                                          prn=self.packet_callback, store=True, count=count)
        except Exception as e:
            print(f"Error al capturar paquetes: {e}")
        else:
            print(f"Captura finalizada. Número de paquetes capturados: {len(self.captured_packets)}")

    @staticmethod
    def packet_callback(packet: Packet) -> Packet:
        print(packet.summary())
        return packet

    def filter_by_protocol(self, protocol: str) -> List[Packet]:
        return [pkt for pkt in self.captured_packets if pkt.haslayer(protocol)]

    def filter_by_text(self, text: str) -> List[Packet]:
        return [pkt for pkt in self.captured_packets if self.packet_contains_text(pkt, text)]

    @staticmethod
    def packet_contains_text(packet: Packet, text: str) -> bool:
        return text.lower() in str(packet).lower()

    def print_packet_details(self, packets: Optional[List[Packet]] = None) -> None:
        packets = packets or self.captured_packets
        for packet in packets:
            packet.show()
            print("-" * 100)

    @staticmethod
    def export_to_pcap(packets: List[Packet], filename: str = "Capture.pcap") -> None:
        try:
            wrpcap(filename, packets)
            print(f"Paquetes guardados en el archivo: {os.path.abspath(filename)}")
        except Exception as e:
            print(f"Error al guardar el archivo: {e}")






