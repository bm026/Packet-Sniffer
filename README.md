### Packet Sniffer

A basic system daemon that logs all incoming and outgoing packets from a machine. Wireshark v0.1, basically.

#### Usage

Requires libpcap.

$ gcc -o sniffer sniffer.c -l pcap  
$ sudo ./sniffer