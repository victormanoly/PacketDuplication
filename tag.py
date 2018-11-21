#probando uso de sockets para modificar paquetes
from struct import *
from socket import *
import binascii, optparse
from scapy.all import *
import difflib


class tag():

    def __init__(self, *args, **kwargs):
        self.iface = "eno1"
        self.s = socket.socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
        self.s.bind((self.iface,0))
        self.tag_count = 1501
        self.dmac = 0
        self.smac = 0
        #self.protot = 0
        #self.payload = 0
        self.rx_pkts()

    #Receive packets in the interface
    def rx_pkts(self):
        print ("Receive Packets")
        self.pkts = self.s.recvfrom(65565)
        print (self.pkts)
        if self.pkts[1][1] == 2048 and self.pkts[1][2] == 0: #ip type and destinated to the host
            self.parse_pkts(self.pkts[0])
        else:
            print ("Send Packet")
            self.s.send(self.pkts[0])  

    #Create Tag
    def tag(self):
        print("Tagging Packets")
        if self.tag_count == 1532:
            self.tag_count = 1501
        tag = (hex(self.tag_count)).replace("0x", "0")
        self.protot = tag.decode("hex")
        self.tag_count += 1
        self.tx_pkts()

    
    #Send tagged packets
    def tx_pkts(self):
        print ("Send Tagged Packet")
        self.n_pkt = self.dmac + self.smac + self.protot + self.payload
        self.s.send(self.n_pkt)
           



    def parse_pkts(self, pkt):
        print ("Parsing Packets")
        
        dmac = binascii.hexlify(pkt[0:6]).decode()
        self.dmac = dmac.decode("hex")

        smac = binascii.hexlify(pkt[6:12]).decode()
        self.smac = smac.decode("hex")

        protot = binascii.hexlify(pkt[12:14]).decode()
        self.protot = protot.decode("hex")

        payload = binascii.hexlify(pkt[14:]).decode()
        self.payload = payload.decode("hex")

        self.tag()

        return

def __main__():
    pd = tag()

if __name__ == '__main__':
    __main__()






    



