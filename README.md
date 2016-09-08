### Packet Sniffer

A tool that inspects all incoming packets to a machine. Wireshark v0.0.1, basically.

#### Usage

Requires libpcap.

$ gcc -o sniffer sniffer.c -l pcap  
$ sudo ./sniffer