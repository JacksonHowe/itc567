# Port Scanner
# Jackson Howe

import argparse
from scapy.all import sr1, IP, TCP, ICMP, UDP
import random
import ipaddress


def random_port():
    # This range of ports is open to use by user applications
    return random.randint(49152, 65535)


def report(host, port, protocol, scan, out):
    if not out:
        print('{}:{}/{} {}'.format(host, port, protocol, scan))
    else:
        out.write('<li>{}:{}/{} {}</li>'.format(host, port, protocol, scan))


# Send a TCP SYN packet - stealthy because we don't complete the TCP handshake
def tcp_syn_scan(host, port, timeout):
    scan = sr1(IP(dst=host)/TCP(sport=random_port(), dport=port, flags='S'), timeout=timeout, verbose=False)
    return 'Open' if scan and scan[TCP].flags == 18 else 'Closed'


# Sends a TCP ACK packet - can only determine filtered/unfiltered status
def tcp_ack_scan(host, port, timeout):
    tcp_ack_filtered_codes = [1, 2, 3, 9, 10, 13]
    scan = sr1(IP(dst=host)/TCP(sport=random_port(), dport=port, flags='A'), timeout=timeout, verbose=False)
    if scan:
        if scan.haslayer(ICMP) and scan.getlayer(ICMP).type == 3 and scan.getlayer(ICMP).code in tcp_ack_filtered_codes:
            return 'Filtered'
        elif scan[TCP].flags == 4:  # RST flag
            return 'Unfiltered'
    return 'Filtered'


# Send a UDP packet - due to the nature of UDP ports, we often don't receive any response and thus sometimes can't
# tell the difference between open and filtered
def udp_scan(host, port, timeout):
    udp_filtered_codes = [1, 2, 9, 10, 13]
    scan = sr1(IP(dst=host)/UDP(sport=random_port(), dport=port), timeout=timeout, verbose=False)
    if scan:
        if scan.haslayer(UDP):
            return 'Open'
        elif scan.haslayer(ICMP) and scan.getlayer(ICMP).type == 3 and scan.getlayer(ICMP).code == 3:  # type 3, code 3 = unreachable
            return 'Closed'
        elif scan.haslayer(ICMP) and scan.getlayer(ICMP).type == 3 and scan.getlayer(ICMP).code in udp_filtered_codes:
            return 'Filtered'
    return 'Open|Filtered'


if __name__ == '__main__':
    # Parse the arguments
    parser = argparse.ArgumentParser(description='A simple port scanning utility')

    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument('--host', type=str, help='Single host to scan')
    host_group.add_argument('--hosts', type=str, help='Range and subnet mask to scan')
    host_group.add_argument('--input', type=str, help='File with list of hosts to scan (1 host per line)')

    parser.add_argument('--port', type=int, help='Port(s) to scan (provide at least 1)', nargs='+')
    parser.add_argument('--type', type=str, help='The protocol and scan type', choices=['syn', 'ack', 'udp'], default='syn')
    parser.add_argument('--timeout', type=int, help='Connection timeout in seconds', default=2)
    parser.add_argument('--output', type=str, help='HTML output file')

    args = parser.parse_args()

    # Put hosts to scan into hosts array depending on input method
    hosts = []
    if args.host:
        hosts.append(args.host)
    elif args.hosts:
        hosts.extend([addr for addr in ipaddress.ip_network(args.hosts).hosts()])
    else:
        with open(args.input) as file:
            file_content = file.readlines()
        hosts.extend([h.strip() for h in file_content])

    # Determine output method and prepare HTML report header if needed
    out = None
    if args.output:
        out = open(args.output, 'w')
        out.write('<h1>Scan Report</h1><p><i>Arguments: {}</i></p><ul>'.format(args))

    # Determine requested scan type, with tcp-syn as default
    protocol = 'TCP-SYN'
    if args.type == 'udp':
        protocol = 'UDP'
    elif args.type == 'ack':
        protocol = 'TCP-ACK'

    # Run the requested scan for each host and port combination
    for h in hosts:
        for p in args.port:
            if protocol == 'UDP':
                scan = udp_scan(h, p, args.timeout)
            elif protocol == 'TCP-ACK':
                scan = tcp_ack_scan(h, p, args.timeout)
            else:
                scan = tcp_syn_scan(h, p, args.timeout)
            report(h, p, protocol, scan, out)

    if out:
        out.write('</ul>')
        out.close()
