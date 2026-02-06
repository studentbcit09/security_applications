import scapy

from scapy.layers.inet import IP_PROTOS
from scapy.all import sniff

ICMP_PROTO_VAL = 1

def traffic_analysis():
    num_packets = 20

    packets =  sniff(filter="ip or ip6", count = num_packets)

    protocol_counts = {}

    print(f"{'Source IP':<15} | {'Source Port':<12} | {'Destination IP':<17} | {'Destination Port':<16} | {'Protocol':<10}")
    print("-" * 75)
    for packet in packets:
        # the filter guarantees that the ip layer will exist
        ip_layer = packet.getlayer('IP')
        # print(ip_layer)
        src = ip_layer.src
        dst = ip_layer.dst
        proto_val = ip_layer.proto 

        if ICMP_PROTO_VAL == proto_val:
            src_port = dst_port = "N/A"
        else:
            payload = ip_layer.payload
            src_port = payload.sport
            dst_port = payload.dport

        proto_str = IP_PROTOS[proto_val]

        if proto_str not in protocol_counts:
            protocol_counts[proto_str] = 1
        else:
            protocol_counts[proto_str] += 1

        print(f"{src:<15} | {src_port:<12} | {dst:<17} | {dst_port:<16} | {proto_str:<10}")
    
    print("-" * 26)
    print(f"{'Protocol':<15} | {'Count':>8}")
    print("-" * 26)
    for proto in protocol_counts:
        print(f"{proto:<15} | {protocol_counts[proto]:>8}")

if __name__ == '__main__':
    traffic_analysis()