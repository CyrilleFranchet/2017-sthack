# Forensic - Le bus magique
We download the challenge file which is named "LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng".
The file command confirms that this is a capture file.

```
cf@front-secu-linux:/mnt/hgfs/sas/challs/sthack-2017/forensic$ file LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng
LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng: pcap-ng capture file - version 1.0
```

We can also check the SHA256 hash of the file.

```
cf@front-secu-linux:/mnt/hgfs/sas/challs/sthack-2017/forensic$ sha256sum LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng
13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802  LebusMagique_13378b8fc9585cb24dfade733f496d631e373cb0595706d4e6235734ee186802.pcapng
```

We open the file with Wireshark to quickly see what is inside the capture.

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-1.png|alt=screen-1]]

Okay, so one more time we have to deal with USB trafic captured by usbmon. If we check quickly the content we can see many URB_INTERRUPT packets between 1.41 and the host and between 1.4.2 and the host.

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-2.png|alt=screen-2]]

The first step is to identify which equipment is connected on the USB port with the ID 1.4.0. To get this answer, we need to find a GET DESCRIPTOR Response DEVICE packet coming from this ID. The dissector tells us that this equipment is from Focusrite-Novation (a quick Google search will tell us that this manufacturer sell audio solutions for musicians). To completely understand what this equipment is doing on the bus we need to find what is behind 0x0036). 

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-3.png|alt=screen-3]]

Some Google searches later, we find an interesting link https://gist.github.com/EllenFawkes/02c8e4b8e0b23aae3847 where we learn that this equipment is actually a Launchpad Mini from Focusrite-Novation. This is a MIDI equipment we can use to play some notes by pushing on the pad buttons. As I’m not a musician myself, I don’t really understand the goal of this pad but we need to go ahead to get the flag. 

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-4.png|alt=screen-4]]

The USB equipment:

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-5.png|alt=screen-5]]

Fortunately, Focusrite-Novation has some good documents to help developers who want to build Application that can interact with the Launchpad Mini.
http://lgnap.helpcomputer.org/wp-content/uploads/2014/09/launchpad-programmers-reference.pdf
By reading this document, we understand two things:
* The Launchpad communicates with the PC
* The PC can also communicates with the Launchpad
Now we understand why we have two IDs, 1.4.1 and 1.4.2. The first one is used to send messages to the PC and the other one is used to received messages from the PC.
In the chapter 4, we also learn that Launchpad Mini communicates which key has been pressed by sending the following message "90h, *key*, *velocity*".
It’s a good news because the capture file has a lot of these messages sent by the Launchpad Mini so it may be a good idea to extract the *key* value from the capture. We also learn that *velocity* has too special values: 7Fh when *key* is pressed and 00h when *key* is released.

We can use Scapy to parse the PCAP file and extract the key value.

[solve_launchpad-1.py](https://github.com/CyrilleFranchet/2017-sthack/blob/master/solve_launchpad_1.py)

This script dumps the key value and we can associate these values with the drum layout which is also included in the documentation.

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-6.png|alt=screen-6]]

But for the moment we don’t see the point of the Launchpad Mini.
At this point we elaborated many theories and only one was correct 😃 Someone is pressing buttons to draw a character on the Launchpad Mini.
If we look again at the capture file, we can see that a list of key presses is always followed by a series of message coming from the PC and sent to the Launchpad Mini.

[[https://github.com/CyrilleFranchet/2017-sthack/blob/master/screen-7.png|alt=screen-7]]

The document explains that the message "80h, *key*, *velocity*" is used to produce the Note Off message (sent from the PC to the Launchpad Mini).
We can guess that this sequence is used to separate characters in the capture.
So now to get the flag we need to reconstruct the matrix of Launchpad Mini and print it when we see the 80h sequence.
The following script displays the matrix of each character (in a way that will make you forget the term Pythonic I guess…).

[solve_launchpad-2.py](https://github.com/CyrilleFranchet/2017-sthack/blob/master/solve_launchpad_2.py)

We get the following message:
FLAGISSHA256OFSTHACK_17_YEAH!

Let’s get the flag then.
```
cf@front-secu-linux:/mnt/hgfs/sas/challs/sthack-2017/forensic$ echo -n "STHACK_17_YEAH!" | sha256sum
2ea0eec35b43437ef94ec456255a5597330f670a82ae8c392bf1660712b00950  -
```

I would like to thank @shoxxdj for this chall. Year after year he is still able to provide interesting PCAP files.
