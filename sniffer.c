#include "h_sniffer.h"

int main (int argc, char *argv[]) {

  struct pcap_pkthdr header;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;
  int i;

  // if incorrect command line arguments, show usage and exit
  if (argc > 2 || (argc == 2 && strcmp(argv[1], "-i") != 0))
    usage(argv[0]);

  // finds device suitable to sniff on
  device = pcap_lookupdev(errbuf);
  if (device == NULL)
    fatal("in pcap_lookupdev");

  printf("Sniffing on device %s\n", device);

  // opens packet-capturing device in promiscuous mode with
  // maximum packet size 4096 bytes
  pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL)
    fatal("in pcap_open_live");

  // captures 10 packets
  for (i=0; i<10; i++) {
    do {
      packet = pcap_next(pcap_handle, &header);
    } while (header.len == 0);
    printf("\nGot a %d byte packet.\n%s\n", header.len, (char *)packet);
    header.len = 0;
  }

  // closes the capturing interface
  pcap_close(pcap_handle);

  return 0;
}