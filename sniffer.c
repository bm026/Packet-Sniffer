#include "h_sniffer.h"

// function prototypes
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet);

// sniffer
int main (int argc, char *argv[]) {

  struct pcap_pkthdr cap_header;
  const u_char *packet, *pkt_data;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;

  // if incorrect command line arguments, show usage and exit
  if (argc > 2 || (argc == 2 && strcmp(argv[1], "-i") != 0))
    usage(argv[0]);

  // finds device suitable to sniff on
  device = pcap_lookupdev(errbuf);
  if (device == NULL)
    fatal("in pcap_lookupdev");

  printf("Sniffing on device %s\n\n", device);

  // opens packet-capturing device not in promiscuous mode with
  // maximum packet size 4096 bytes
  pcap_handle = pcap_open_live(device, 4096, 0, 0, errbuf);
  if (pcap_handle == NULL)
    fatal("in pcap_open_live");

  // captures 10 packets
  /*for (i=0; i<10; i++) {
    do {
      packet = pcap_next(pcap_handle, &header);
    } while (header.len == 0);
    printf("Got a %d byte packet.\n%s\n\n", header.len, (char *)packet);
    header.len = 0;
  }*/

  // captures packets until ^C
  pcap_loop(pcap_handle, -1, caught_packet, NULL);

  // closes the capturing interface
  pcap_close(pcap_handle);

  return 0;
}

void *print_ip(unsigned int addr) {
  int ip[4];
  char ip_string[20];
  char itoa[4];
  unsigned int ip_whole = ntohl(addr);
  ip[0] = ip_whole >> 24;
  ip[1] = (ip_whole >> 16) & 0xff;
  ip[2] = (ip_whole >> 8) & 0xff;
  ip[3] = ip_whole & 0xff;
  sprintf(itoa, "%d", ip[0]);
  strcpy(ip_string, itoa);
  strncat(ip_string, ".", 1);
  sprintf(itoa, "%d", ip[1]);
  strcat(ip_string, itoa);
  strncat(ip_string, ".", 1);
  sprintf(itoa, "%d", ip[2]);
  strcat(ip_string, itoa);
  strncat(ip_string, ".", 1);
  sprintf(itoa, "%d", ip[3]);
  strcat(ip_string, itoa);
  printf("%s", ip_string);
}

// deals with captured raw data packets
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

  const struct ip_hdr *ip_header;
  const struct tcp_hdr *tcp_header;
  int tcp_header_length, total_header_size, packet_data_length;

  printf("=== Got a %d byte packet ===\n", cap_header->len);

  // get IP addresses of packet
  const u_char *ip_hdr_start = packet + ETHER_HDR_LEN;
  ip_header = (const struct ip_hdr *) ip_hdr_start;

  printf("Source:\t\t"); //inet_ntoa(ip_header->ip_src_addr));
  print_ip(ip_header->ip_src_addr); printf("\n");
  printf("Destination:\t"); //inet_ntoa(ip_header->ip_dest_addr));
  print_ip(ip_header->ip_dest_addr); printf("\n");

  // get length of TCP header
  const u_char *tcp_hdr_start = packet + ETHER_HDR_LEN + sizeof(struct ip_hdr);
  tcp_header = (const struct tcp_hdr *) tcp_hdr_start;
  tcp_header_length = 4 * tcp_header->tcp_offset;

  // get data
  total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
  packet_data_length = cap_header->len - total_header_size;

  // if data, print size
  if (packet_data_length > 0) {
    printf("Data:\t\t%d bytes\n\n", packet_data_length);
  }
  // if no data, print flags
  else {
    printf("No data. Flags:\t");
    if (tcp_header->tcp_flags & TCP_FIN) printf("FIN ");
    if (tcp_header->tcp_flags & TCP_SYN) printf("SYN ");
    if (tcp_header->tcp_flags & TCP_RST) printf("RST ");
    if (tcp_header->tcp_flags & TCP_PUSH) printf("PUSH ");
    if (tcp_header->tcp_flags & TCP_ACK) printf("ACK ");
    if (tcp_header->tcp_flags & TCP_URG) printf("URG");
    printf("\n\n");
  }

}