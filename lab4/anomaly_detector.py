import scapy.all as scapy
from scapy.layers.inet import IP_PROTOS

import logging

logging.basicConfig(
    filename='lab_debug.log', 
    level=logging.DEBUG, 
    format='%(asctime)s | %(levelname)s | %(message)s'
)

IP_PROTOS_UDP = 17
IP_PROTOS_TCP = 6

def anomaly_detector():

    protocol_counts = {}
    detection_count = {}

    suspicious_ips = []

    for frame, packet in enumerate(scapy.PcapReader("botnet-capture-20110812-rbot.pcap"), start=1):
        if 'IP' in packet:
            ip_layer = packet.getlayer('IP')
            src = ip_layer.src
            dst = ip_layer.dst
            
            proto_val = ip_layer.proto
            ts = packet.time

            if src in detection_count:
                detection_count[src].append(ts)
                if src not in suspicious_ips:
                    prev_pkts = detection_count[src]
                    boundary_ts = ts - 5

                    for prev_ts in prev_pkts[:]:
                        if prev_ts < boundary_ts:
                            prev_pkts.pop(0)
                        else:
                            break
                    
                    num_pkts = len(prev_pkts)
                    if num_pkts >= 20:
                        print(f"ALERT: More than 20 packets received from {src}")
                        suspicious_ips.append(src)
            else:
                detection_count[src] = [ts]

            proto_str = IP_PROTOS[proto_val]
            if proto_str not in protocol_counts:
                protocol_counts[proto_str] = 1
            else:
                protocol_counts[proto_str] += 1
        else:
            logging.info(f"Frame {frame} is not a layer 4 packet")

    print(f"Total TCP packets: {protocol_counts['tcp']}")
    print(f"Total TCP packets: {protocol_counts['udp']}")
    print(f"Total suspicious IPs detected: {len(suspicious_ips)}")

if __name__ == '__main__':
    anomaly_detector()