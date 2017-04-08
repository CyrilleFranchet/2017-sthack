from scapy.all import *

f = rdpcap('LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng')
launchpad = [ [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0],
              [ 0, 0, 0, 0, 0, 0, 0, 0] ]

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
                key = data[2]
		if key == '\x24':
			launchpad[7][0] = 1
		elif key == '\x25':
			launchpad[7][1] = 1
		elif key == '\x26':
			launchpad[7][2] = 1
		elif key == '\x27':
			launchpad[7][3] = 1
		elif key == '\x28':
			launchpad[6][0] = 1
		elif key == '\x29':
			launchpad[6][1] = 1
		elif key == '\x2a':
			launchpad[6][2] = 1
		elif key == '\x2b':
			launchpad[6][3] = 1
		elif key == '\x2c':
			launchpad[5][0] = 1
		elif key == '\x2d':
			launchpad[5][1] = 1
		elif key == '\x2e':
			launchpad[5][2] = 1
		elif key == '\x2f':
			launchpad[5][3] = 1
		elif key == '\x30':
			launchpad[4][0] = 1
		elif key == '\x31':
			launchpad[4][1] = 1
		elif key == '\x32':
			launchpad[4][2] = 1
		elif key == '\x33':
			launchpad[4][3] = 1
		elif key == '\x34':
			launchpad[3][0] = 1
		elif key == '\x35':
			launchpad[3][1] = 1
		elif key == '\x36':
			launchpad[3][2] = 1
		elif key == '\x37':
			launchpad[3][3] = 1
		elif key == '\x38':
			launchpad[2][0] = 1
		elif key == '\x39':
			launchpad[2][1] = 1
		elif key == '\x3a':
			launchpad[2][2] = 1
		elif key == '\x3b':
			launchpad[2][3] = 1
		elif key == '\x3c':
			launchpad[1][0] = 1
		elif key == '\x3d':
			launchpad[1][1] = 1
		elif key == '\x3e':
			launchpad[1][2] = 1
		elif key == '\x3f':
			launchpad[1][3] = 1
		elif key == '\x40':
			launchpad[0][0] = 1
		elif key == '\x41':
			launchpad[0][1] = 1
		elif key == '\x42':
			launchpad[0][2] = 1
		elif key == '\x43':
			launchpad[0][3] = 1
		elif key == '\x44':
			launchpad[7][4] = 1
		elif key == '\x45':
			launchpad[7][5] = 1
		elif key == '\x46':
			launchpad[7][6] = 1
		elif key == '\x47':
			launchpad[7][7] = 1
		elif key == '\x48':
			launchpad[6][4] = 1
		elif key == '\x49':
			launchpad[6][5] = 1
		elif key == '\x4a':
			launchpad[6][6] = 1
		elif key == '\x4b':
			launchpad[6][7] = 1
		elif key == '\x4c':
			launchpad[5][4] = 1
		elif key == '\x4d':
			launchpad[5][5] = 1
		elif key == '\x4e':
			launchpad[5][6] = 1
		elif key == '\x4f':
			launchpad[5][7] = 1
		elif key == '\x50':
			launchpad[4][4] = 1
		elif key == '\x51':
			launchpad[4][5] = 1
		elif key == '\x52':
			launchpad[4][6] = 1
		elif key == '\x53':
			launchpad[4][7] = 1
		elif key == '\x54':
			launchpad[3][4] = 1
		elif key == '\x55':
			launchpad[3][5] = 1
		elif key == '\x56':
			launchpad[3][6] = 1
		elif key == '\x57':
			launchpad[3][7] = 1
		elif key == '\x58':
			launchpad[2][4] = 1
		elif key == '\x59':
			launchpad[2][5] = 1
		elif key == '\x5a':
			launchpad[2][6] = 1
		elif key == '\x5b':
			launchpad[2][7] = 1
		elif key == '\x5c':
			launchpad[1][4] = 1
		elif key == '\x5d':
			launchpad[1][5] = 1
		elif key == '\x5e':
			launchpad[1][6] = 1
		elif key == '\x5f':
			launchpad[1][7] = 1
		elif key == '\x60':
			launchpad[0][4] = 1
		elif key == '\x61':
			launchpad[0][5] = 1
		elif key == '\x62':
			launchpad[0][6] = 1
		elif key == '\x63':
			launchpad[0][7] = 1
    
    # From computer to Launchpad
    if endpoint == '\x02' and transfert_type == '\x01':
        data = t[-4:]
        if data[1] == '\x80':
            if not end:
                for line in launchpad:
                    print line
		end = True
		launchpad = [ [ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0],
              			[ 0, 0, 0, 0, 0, 0, 0, 0] ]
