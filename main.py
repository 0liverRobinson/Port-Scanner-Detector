import string
from telnetlib import IP
from time import sleep
from xmlrpc.client import boolean
from scapy.all import *
from threading import Thread

# Data structure to hold all the data of the packet
class PacketCap:
    def __init__(self, source_ip, destination_ip, source_port, destination_port, packet_captured) -> None:

        # Initialise main packet data
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port 

        # Format packet into hex dump
        temp = packet_captured.lastlayer()
        self.packet_captured = hexdump(temp, dump=True)

        # Create head of linked list
        self.nextNode = None

        # The length of the linked list
        self.tailLength = 1
        pass
    
    def print_details(self):
        # Print out the packets details
        print("(", self.source_ip, ", ", self.source_port, ", ", self.destination_ip, ", ", self.destination_port, ")")
        pass
    


def writeLog(log_file, packet_cap):
    # Write into the file
    log_file.write("Source IP ["+packet_cap.source_ip+"] Destination IP ["+packet_cap.destination_ip+"] Source Port ["+packet_cap.source_port+"] Destination Port["+packet_cap.destination_port+"]\n\n")
    
    # Write the packet data into the file
    log_file.write(str(packet_cap.packet_captured))
    
    # Add Splitting line to the file
    log_file.write("\n\n------------------------------------------------------------------\n")
    pass

def detect_port_scan():

    while True:
        # Wait to aquire a lock
        while not dictionary_lock.acquire():
            continue
        # Remove packet lists from capture
        remove_list = []
        for _, packet_cap in packet_dictionary_buffer.items():
            # Check to see if its over the threshhold
                if (packet_cap.tailLength >= PORT_COUNT_THRESHOLD):
                    # Alert the user of suspicious activity
                    if (packet_cap.source_ip not in attackers_packets_dictionary):
                        print("[", packet_cap.source_ip,"\033[91m\033[1mDETECTED PORT SCANNING\033[0m ]")
                        # Append to the unsafe packet dictionary
                        attackers_packets_dictionary[packet_cap.source_ip] = packet_cap
                    # Open the log file to do with the IP address
                    log_file = open( "logs/" + packet_cap.source_ip.replace(".", "_") + ".log", "a")
                    # Write to the file
                    writeLog(log_file, packet_cap)
                    # Close file
                    log_file.close()
                    remove_list.append(packet_cap.source_ip)
        dictionary_lock.release()
        # Remove printed packets from packet dictionary
        for ip_address in remove_list:
            del packet_dictionary_buffer[ip_address]


def isNewPort(packet_cap: PacketCap, selected_port: string) -> boolean:
    # If we have reached the final packet, return True (we didn't detect a matching port during the traversal)
    if (packet_cap == None):
        return True
    else:
        # If the port is in the linked list, then return false
        if (packet_cap.source_port == selected_port):
            return False
        # Recurse until we reach the last packet
        isNewPort(packet_cap.nextNode, selected_port)
    return True


def deconstruct_packet(packet_captured):
    try:
        # Get Packet details
        source_ip = str  ( packet_captured[IP].src )
        destination_ip = str  ( packet_captured[IP].dst )

        # It its our IP address, just ignore it...    
        if (source_ip in host_ip or host_ip in source_ip or host_ip == source_ip):
            return

        # If it's a TCP packet then analyse it
        if ("TCP" in packet_captured):

            # Get ports
            destination_port = str  ( packet_captured.dport )
            source_port = str  ( packet_captured.sport )

            # Create a packetcap 
            compiled_packet = PacketCap(source_ip, destination_ip, source_port, destination_port, packet_captured)

            # Aquire lock
            while not dictionary_lock.acquire():
                continue
                
            if ( source_ip not in packet_dictionary_buffer ):
            # Create a new key in the dictionary
                packet_dictionary_buffer[source_ip] = compiled_packet
                dictionary_lock.release()
                 
            else:
            # Add to the start of a dictionary linked list
                compiled_packet.tailLength = 1 + packet_dictionary_buffer[source_ip].tailLength    # Increase head's leangth by one from the last 
                compiled_packet.nextNode = packet_dictionary_buffer[source_ip]                     # Set head next to the rest of the list
                if (isNewPort(packet_dictionary_buffer[source_ip], source_port)):                  # Determine weatehr we are scanning a new port or not
                    packet_dictionary_buffer[source_ip] = compiled_packet                          # If we are scanning a new port, add it to the linked list
                del attackers_packets_dictionary[source_ip]
                dictionary_lock.release()                

    except:
        pass

    pass



def fetch_thread():
    # Fetch traffic going in/out
    while True:
        sniff(count=1, prn=deconstruct_packet, store=0)


if __name__ == "__main__":

    # Threshold for how many ports someone has to touch before detemining it as a port scan
    PORT_COUNT_THRESHOLD = 100
    
    # Get IP address
    host_ip = str ( get_if_addr(conf.iface) ).replace(" ", "")

    # Lock for safe editing of the IP-PORT dictionary
    dictionary_lock = threading.Lock()
    
    # Dictionaries for current packets and unsafe packets
    packet_dictionary_buffer = { }
    attackers_packets_dictionary = { }

    # Start program
    Thread(target=fetch_thread).start()                                                     # Fetch Data
    Thread(target=detect_port_scan).start()                                                 # Handle Data

    pass
