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

  // captures packets until ^C
  pcap_loop(pcap_handle, -1, caught_packet, NULL);

  // closes the capturing interface
  pcap_close(pcap_handle);

  return 0;
}

// deals with captured raw data packets
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

  const struct ip_hdr *ip_header;
  const struct tcp_hdr *tcp_header;
  int tcp_header_length, total_header_size, packet_data_length;
  struct in_addr inet_ip;
  struct in_addr inet_ip_this;

  //printf("=== Got a %d byte packet ===\n", cap_header->len);

  // get IP addresses of packet
  const u_char *ip_hdr_start = packet + ETHER_HDR_LEN;
  ip_header = (const struct ip_hdr *) ip_hdr_start;

  // print source and destination IPs
  /*inet_ip.s_addr = ip_header->ip_src_addr;
  printf("Source:\t\t%s\n", inet_ntoa(inet_ip));
  inet_ip.s_addr = ip_header->ip_dest_addr;
  printf("Destination:\t%s\n", inet_ntoa(inet_ip));*/

  // only logs packets with destination 192.168.1.35
  if (inet_aton("192.168.1.35", &inet_ip_this) == 0) fatal("in IP conversion");
  if (inet_ip_this.s_addr == ip_header->ip_dest_addr) {

    // create timestamp
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char time_string[30];
    sprintf(time_string, "%d-%02d-%02d %02d:%02d:%02d >", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("%s\t", time_string);
    
    // get source IP address
    inet_ip.s_addr = ip_header->ip_src_addr;
    printf("%s\t", inet_ntoa(inet_ip));

    // get length of TCP header
    const u_char *tcp_hdr_start = packet + ETHER_HDR_LEN + sizeof(struct ip_hdr);
    tcp_header = (const struct tcp_hdr *) tcp_hdr_start;
    tcp_header_length = 4 * tcp_header->tcp_offset;

    // get data size
    total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
    packet_data_length = cap_header->len - total_header_size;

    // if data, print size
    if (packet_data_length > 0) {
      //printf("Data:\t\t%d bytes\n\n", packet_data_length);
      printf("%d bytes\t", packet_data_length);
    }
    // if no data, print flags
    else {
      printf("No data. Flags: ");
      if (tcp_header->tcp_flags & TCP_FIN) printf("FIN ");
      if (tcp_header->tcp_flags & TCP_SYN) printf("SYN ");
      if (tcp_header->tcp_flags & TCP_RST) printf("RST ");
      if (tcp_header->tcp_flags & TCP_PUSH) printf("PUSH ");
      if (tcp_header->tcp_flags & TCP_ACK) printf("ACK ");
      if (tcp_header->tcp_flags & TCP_URG) printf("URG");
      //printf("\n\n");
    }
    printf("\n");
  }
}