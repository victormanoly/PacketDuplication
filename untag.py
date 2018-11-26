from struct import *
from socket import *
import binascii, optparse
#from scapy.all import *

class UnTag():

    def __init__(self, *args, **kwargs):
        self.iface = "enp0s3"
        self.tag_list = []
        self.s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
        self.protoip = ((hex(2048)).replace("0x", "0")).decode('hex')
        self.s.bind((self.iface,0))
        self.rx_pkts()



    #Receive packets in the interface
    def rx_pkts(self):
        while True:
            print ("Receive Packets")
            self.pkts = self.s.recvfrom(65565)
            print (self.pkts)
            self.parse_pkts(self.pkts[0])
            

    #Send untagged packets
    def tx_pkts(self):
        print ("Send UnTagged Packet")
        self.untag_pkt = self.dmac + self.smac + self.protoip + self.payload
        self.s.send(self.untag_pkt)

    def untag(self):
        print("untagging")
        if self.protot not in self.tag_list: 
            self.tag_list.append(self.protot)
            if self.protot == 1531:
                self.tag_list = []
            self.tx_pkts()
        self.rx_pkts()

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
        

        if int(protot,16) > 1500 and int(protot,16) <= 1531: # and self.pkts[1][2] == 0: #ip type and destinated $
            self.untag()
        #else:
        #    print ("Send Packet")
        #    self.s.send(self.pkts[0])




def __main__():
    pd = UnTag()

if __name__ == '__main__':
    __main__()
