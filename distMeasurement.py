import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import select
import socket
import struct
import time
from datetime import datetime


MESSAGE = 'measurement for class project. questions to student cpt15@case.edu or professor mxr136@case.edu'
PAYLOAD = bytes(MESSAGE + 'a'*(1472 - len(MESSAGE)), 'ascii')

MAX_HOPS = 64
PROBE_PORT = 33434
MAX_NUM_ATTEMPTS = 3
DATE_AND_TIME = datetime.now().strftime("%m_%d_%Y__%H_%M_%S")


def measure_site(hostname):
    try:
        # Look up the ip address for the server by hostname
        dest_address = socket.gethostbyname(hostname)
    except:
        print("\tUnable to resolve host: " + hostname)
        return -1, -1, False, False, -1

    #create sending socket
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, MAX_HOPS)

    # Create Receiving socket
    timeout = struct.pack("ll", 5, 0)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    recv_sock.bind(('', PROBE_PORT))

    # send the payload to the specified address
    time_sent = time.perf_counter()
    send_sock.sendto(PAYLOAD, (dest_address, PROBE_PORT))
    arrv = select.select([recv_sock], [], [], 2)

    ip_match = False
    port_match = False

    num_attempts = 0

    while not (ip_match or port_match) and num_attempts < MAX_NUM_ATTEMPTS:
        try:
            # receive the packet
            recv_packet, address = recv_sock.recvfrom(1500)

            # Set the time the packet is received
            time_received = time.perf_counter()

            # Calculate the remaining length of the payload in the received packet
            icmp_ip_header = struct.unpack('!BBHHHBBH4s4s', recv_packet[0:20])
            icmp_packet_length = icmp_ip_header[2]
            original_packet_remaining_payload_length = icmp_packet_length - 56

            # Unpack the ip header contained within the icmp packet payload
            payload_ip_header = struct.unpack('!BBHHHBBH4s4s', recv_packet[28:48])

            # Extract the response address
            resp_address = socket.inet_ntoa(payload_ip_header[9])

            # Extract Payload UDP headers
            payload_udp_headers = struct.unpack('!HHHH', recv_packet[48:56])

            # extract the payload port
            resp_port = payload_udp_headers[1]

            # Check for the various matches
            ip_match = (dest_address == resp_address)
            port_match = (PROBE_PORT == resp_port)

            if ip_match or port_match:
                remaining_ttl = payload_ip_header[5]
                # Calculate the number of hops and rtt
                num_hops = MAX_HOPS - remaining_ttl
                rtt = time_received - time_sent

                send_sock.close()
                recv_sock.close()
                return num_hops, float(rtt*1000), ip_match, port_match, original_packet_remaining_payload_length

        except socket.error:
            # Increase the number of attempts made
            num_attempts += 1
            print("\tUnable to reach host: " + hostname + " --> Trying " + str(MAX_NUM_ATTEMPTS-num_attempts) + " more times.")
            # Reset timer and resend packet
            time_sent = time.perf_counter()
            send_sock.sendto(PAYLOAD, (dest_address, PROBE_PORT))

    send_sock.close()
    recv_sock.close()
    return -1, -1, False, False, -1


def main():
    #Read all sites into an array
    sites = open("targets.txt").read().splitlines()

    #Write output to csv file for import into excel
    file_out = open("output/output_" + DATE_AND_TIME + ".csv",'w')
    file_out.write('%s, %s, %s, %s, %s, %s, %s\n' % ("Host", "IP Match", "Port Match", "Num Hops", "RTT", "Number of Original Message Bytes remaining in ICMP error", "Number of bytes remaining including headers"))

    #Loop through all sites
    for site in sites:
        print("Site: " + site)
        hops, rtt, ip_match, port_match, rem_bytes = measure_site(site)
        if hops > -1 and rtt > -1:
            print("\tNumber of Hops: " + str(hops))
            print("\tRTT (msec): " + str(rtt))
            # This is the number of bytes remaining of the original datagram PAYLOAD (so the contents of the PAYLOAD variable above) which
            # Does not include the IP or UDP headers
            print("\tBytes of original datagram payload remaining (no headers): " + str(rem_bytes))
            print("\tBytes of original datagram remaining (including orig headers): " + str(rem_bytes + 28))
            print("\tIPs Match: " + str(ip_match))
            print("\tPorts Match: " + str(port_match))
            # Write values to CSV file
            file_out.write('%s, %s, %s, %d, %f, %d, %d\n' % (site, ip_match, port_match, hops, rtt, rem_bytes, (rem_bytes + 28)))

            # Add values for this site to the plot
            plt.scatter(hops, rtt, label=site, s=20.0)
        else:
            print("\tUnable to reach site.")

        # Setup the output plot
        plt.xlabel("Hops")
        plt.ylabel("RTT (ms)")
        plt.title("Correlation of Hops vs. RTT")
        plt.legend(fontsize='x-small')
        plt.savefig("output/correlation_" + DATE_AND_TIME + ".png")
    exit()


if __name__ == '__main__':
    main()