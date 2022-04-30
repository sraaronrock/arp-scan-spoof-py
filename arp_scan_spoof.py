from scapy.all import *

def handle_packet(packet):
    if packet[ARP].op == 1:
        if packet.pdst == "192.168.20.152":
         print("Sending ARP response")
         reply = ARP(op=2,
                    hwsrc="00:0C:29:3I:1T:6F",
                    psrc="192.168.20.152",
                    hwdst="00:0C:6C:3D:6A:6F",
                    pdst="192.168.20.255")

        pkt = Ether(dst="00:0C:6C:3D:6A:6F", src="00:0C:29:3I:1T:6F") / reply
        sendp(pkt)
	    
sniff(filter="arp", prn=handle_packet)
