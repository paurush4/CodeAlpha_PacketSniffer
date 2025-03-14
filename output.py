import time
from abc import ABC, abstractmethod


class Output(ABC):
    """Interface for the implementation of all classes responsible for
    further processing/output of the information gathered by the
    PacketSniffer class."""

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass


i = " " * 4  # Basic indentation level


class OutputToScreen(Output):
    def __init__(self, subject, *, display_data: bool):
        """Output data from a decoded frame to screen.

        :param subject: Instance of PacketSniffer to be observed.
        :param display_data: Boolean specifying the output of captured
            data.
        """
        super().__init__(subject)
        self._frame = None
        self._display_data = display_data
        self._initialize()

    @staticmethod
    def _initialize() -> None:
        print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
              "data. Press Ctrl-C to abort...\n")

    def update(self, frame) -> None:
        self._frame = frame
        self._display_output_header()
        self._display_protocol_info()
        self._display_packet_contents()

    def _display_output_header(self) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime())
        print(f"\n{'-'*50}")
        print(f"[>] Frame #{self._frame.packet_num} at {local_time}:")
        print(f"{i}Interface: {self._frame.interface or 'all'}")
        print(f"{i}Frame Length: {self._frame.frame_length}")
        print(f"{i}Epoch Time: {self._frame.epoch_time:.6f}")

    def _display_protocol_info(self) -> None:
        """Iterate through protocol queue and call appropriate display method."""
        for proto in self._frame.protocol_queue:
            method_name = f"_display_{proto.lower()}_data"
            if hasattr(self._frame, proto.lower()):
                if hasattr(self, method_name):
                    getattr(self, method_name)()
                else:
                    print(f"{i}[+] Unknown Protocol: {proto} (No display method)")
            else:
                print(f"{i}[+] Unknown Protocol: {proto} (No attribute found)")

    def _display_ethernet_data(self) -> None:
        eth = self._frame.ethernet
        print(f"{i}[+] Ethernet ....{eth.src} -> {eth.dst}")

    def _display_ipv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        print(f"{i}[+] IPv4 ....{ipv4.src} -> {ipv4.dst}")
        print(f"{2*i}Traffic Class: {ipv4.dscp}")
        print(f"{2*i}Total Length: {ipv4.len} | ID: {ipv4.id}")
        print(f"{2*i}Flags: {ipv4.flags_str} | TTL: {ipv4.ttl}")
        print(f"{2*i}Protocol: {ipv4.encapsulated_proto} | Checksum: {ipv4.chksum_hex_str}")

    def _display_ipv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        print(f"{i}[+] IPv6 ....{ipv6.src} -> {ipv6.dst}")
        print(f"{2*i}Traffic Class: {ipv6.tclass_hex_str} | Flow Label: {ipv6.flabel_txt_str}")
        print(f"{2*i}Payload Length: {ipv6.payload_len} | Hop Limit: {ipv6.hop_limit}")

    def _display_tcp_data(self) -> None:
        tcp = self._frame.tcp
        print(f"{i}[+] TCP ....{tcp.sport} -> {tcp.dport}")
        print(f"{2*i}Sequence Number: {tcp.seq} | ACK: {tcp.ack}")
        print(f"{2*i}Flags: {tcp.flags_hex_str} ({tcp.flags_str})")
        print(f"{2*i}Window Size: {tcp.window} | Checksum: {tcp.chksum_hex_str}")
        print(f"{2*i}Urgent Pointer: {tcp.urg}")

    def _display_udp_data(self) -> None:
        udp = self._frame.udp
        print(f"{i}[+] UDP ....{udp.sport} -> {udp.dport}")
        print(f"{2*i}Length: {udp.len} | Checksum: {udp.chksum}")

    def _display_icmpv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        icmpv4 = self._frame.icmpv4
        print(f"{i}[+] ICMPv4 ....{ipv4.src} -> {ipv4.dst}")
        print(f"{2*i}Type: {icmpv4.type} ({icmpv4.type_str}) | Checksum: {icmpv4.chksum_hex_str}")

    def _display_icmpv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        icmpv6 = self._frame.icmpv6
        print(f"{i}[+] ICMPv6 ....{ipv6.src} -> {ipv6.dst}")
        print(f"{2*i}Type: {icmpv6.type} ({icmpv6.type_str}) | Subtype: {icmpv6.code}")
        print(f"{2*i}Checksum: {icmpv6.chksum_hex_str}")

    def _display_arp_data(self) -> None:
        arp = self._frame.arp
        if arp.oper == 1:
            print(f"{i}[+] ARP Who has {arp.tpa} ? -> Tell {arp.spa}")
        else:
            print(f"{i}[+] ARP {arp.spa} -> Is at {arp.sha}")

        print(f"{2*i}Hardware Type: {arp.htype} | Protocol Type: {arp.ptype_str} ({arp.ptype_hex_str})")
        print(f"{2*i}Operation: {arp.oper} ({arp.oper_str})")
        print(f"{2*i}Sender MAC: {arp.sha} | Sender IP: {arp.spa}")
        print(f"{2*i}Target MAC: {arp.tha} | Target IP: {arp.tpa}")

    def _display_packet_contents(self) -> None:
        if self._display_data and self._frame.data:
            print(f"{i}[+] DATA:")
            data = self._frame.data.decode(errors="ignore").replace("\n", f"\n{2*i}")
            print(f"{i}{data}")

        print(f"{'-'*50}")
