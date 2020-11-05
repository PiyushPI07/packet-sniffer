import socket,struct,binascii,os
import utilities
import pcapy
import time                                                     #time shown on ststus bar
from pcapy import findalldevs,open_live                         #Finding all interfaces on the computer
from impacket import ImpactDecoder, ImpactPacket                #Decoding the Raw Packets Captured
import _thread                                                   #Threading the Sniffer so it will not freeze the mainloop of GUI    
import sys 
from struct import *
import datetime
dev = ''
devices = pcapy.findalldevs()

errbuf = ""

#ask user to enter device name to sniff
print ("Available devices are :")
for d in devices :
    print (d)

dev = input("Enter device name to sniff : ")


def func(protocol):
    pc = open_live('wlp3s0', 65536, True, 1000)
    pc.setfilter(protocol)
    datalink = pc.datalink()
    mask = pc.getmask()
    net = pc.getnet()
    def processPacket(hdr, data):                       #A Function name processPacket
        print ("Listening on wlp3s0 interface: net={}, mask={}, linktype={}".format( net, mask,datalink))
        decoder = ImpactDecoder.EthDecoder()            #use of Decoder module and method
        packet=decoder.decode(data)                     #here data is the raw data capture by pcapy's open_live function
        tcppacket=packet.child()                        #TCP packets
        print( tcppacket )                                #Final capture Packets are printed on console 
    packet_limit = -1                                   #local variable set for looping the printing of live packet captures
    pc.loop(packet_limit, processPacket)  

def head(dev):
    #list all devices

    print ("Sniffing device " + dev)

    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    socket.setdefaulttimeout(2)
    s = socket.socket();
    #s.settimeout(100);    

    #dev = 'eth0' 
    cap = pcapy.open_live(dev , 65536 , 1 , 1000)

   #start sniffing packets
    while(1) :
        (header, packet) = cap.next()
        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet)
        print('--------------------------------------------------------------------------------------------')

    #start sniffing packets
    #while(1) :

    #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "{}:{}:{}:{}:{}:{}".format(ord(chr(a[0])) , ord(chr(a[1])) , ord(chr(a[2])), ord(chr(a[3])), ord(chr(a[4])) , ord(chr(a[5])))
    return b

#function to parse a packet
def parse_packet(packet) :

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print ('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
)
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
)
        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            #print 'Data : ' + data

        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            #print 'Data : ' + data

        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            #print 'Data : ' + data

        #some other IP packet like IGMP
        else :
            print ('Protocol other than TCP/UDP/ICMP')
        



mode  = input("Enter 0 for Packet-header mode and 1 for Data-decode mode \n")
if mode == '1':
    try:
        print("--------------------RUNNING SNIFFER IN DATA DECODING MODE---------------------")
        protocol = input("Enter protocol of the packets to sniff: \n")
        func(protocol)
    except:
        print("Looks like something is wrong!")
        sys.exit()
if mode == '0':
    print("--------------------RUNNING SNIFFER IN PACKET HEADER INFO MODE---------------------")
    head(dev)