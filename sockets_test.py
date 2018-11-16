#probando uso de sockets para modificar paquetes
from struct import *
from socket import *

iface = "wlp3s0"


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))


while True:
    packet = s.recvfrom(65565)
	
	#packet string from tuple
    packet = packet[0]
	
	#parse ethernet header
    eth_length = 14
	
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = ntohs(eth[2])
    print ('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))

