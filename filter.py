from sys import flags
import requests
import argparse
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--filename", dest="filename")
    options = parser.parse_args()

    if options.filename:
        return options.filename
    else:
        parser.error('Invalid Syntax!')

def print_packets(pcap, protocol):
    for timestamp, buf in  pcap:
        #Unpack the Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)

        #check for IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        #IP packet
        ip = eth.data

        #check for TCP in transport layer segment
        if isinstance(ip.data, dpkt.tcp.TCP) and protocol == 'TCP':
            print(f'Timestamp: {str(datetime.datetime.utcfromtimestamp(timestamp))}')
            print('Transport Layer: TCP')

            #obtain TCP segment
            tcp = ip.data

            #obtain flag bits in segment header
            syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
            fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0     
            ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
            rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0

            #sequence number of segment
            seq_num = tcp.seq

            #Acknowledgment number of segment
            ack_num = tcp.ack

            if syn_flag == True:
                syn_flag = 1
            else:
                syn_flag = 0
            if fin_flag == True:
                fin_flag = 1
            else:
                fin_flag = 0
            if ack_flag == True:
                ack_flag = 1
            else:
                ack_flag = 0
            if rst_flag == True:
                rst_flag = 1
            else:
                rst_flag = 0

            #Print TCP segment details
            print(f'Source Port: {tcp.sport}    Destination Port: {tcp.dport}')
            print(f'SYN = {syn_flag}    FIN = {fin_flag}    ACK = {ack_flag}    RST = {rst_flag}    Sequence Number = {seq_num}     Acknowledgment Number = {ack_num}')
        elif isinstance(ip.data, dpkt.udp.UDP) and protocol == 'UDP':
            print(f'Timestamp: {str(datetime.datetime.utcfromtimestamp(timestamp))}')
            print('Transport Layer: UDP')
            udp = ip.data
            print(f'Source Port: {udp.sport}    Destination Port: {udp.dport}')
        else:
            continue
        
        #Network Layer
        print(f'Network Layer:: Source IP: {socket.inet_ntoa(ip.src)}  Destination IP: {socket.inet_ntoa(ip.dst)}')

        #Link Layer
        print(f'Ethernet Frame:: Source MAC: {mac_addr(eth.src)}    Destination MAC: {mac_addr(eth.dst)}')

        #Obtain MAC address of source
        macaddr = mac_addr(eth.src)
        try:
            vendor_name = get_mac_details(macaddr)
            print(f'Device vendor is {vendor_name}')
        except:
            print('Device vendor not found!')
        print()

def get_mac_details(mac_address):
    #API to get mac address
    url = 'https://api.macvendors.com/'

    response = requests.get(url + mac_address)
    if response.status_code != 200:
        raise Exception('Invalid MAC Address!')
    return response.content.decode()

def main():
    filename = get_arguments()
    protocol = input('Enter transport layer protocol: ').upper()
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap, protocol)

if __name__ == '__main__':
    main()