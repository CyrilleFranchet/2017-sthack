from scapy.all import *

f = rdpcap('LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng')

for packet in f:
    t = str(packet)
    transfert_type = t[9]
    endpoint = t[10]
    # From Launchpad to computer
    if endpoint == '\x81' and transfert_type == '\x01':
        data = t[-4:]
        if data[1] == '\x90':
            end = False
	    if data[3] == '\x7f':
                print 'Grid button pressed %s %s ' % (str(data[2]).encode('hex'),
                    str(data).encode('hex'))
