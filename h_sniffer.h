#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ethernet length values
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

// ethernet header struct
struct ether_hdr {
  unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // destination MAC address
  unsigned char ether_src_addr[ETHER_ADDR_LEN];  // source MAC address
  unsigned short ether_type;                     // type of ethernet packet
};

// ip header struct
struct ip_hdr {
  unsigned char ip_version_and_header_length; // version and header length
  unsigned char ip_tos;                       // type of service
  unsigned short ip_len;                      // total length
  unsigned short ip_id;                       // identification number
  unsigned short ip_frag_offset;              // fragment offset and flags
  unsigned char ip_ttl;                       // time to live
  unsigned char ip_type;                      // protocol type
  unsigned short ip_checksum;                 // checksum
  unsigned int ip_src_addr;                   // source IP address
  unsigned int ip_dest_addr;                  // destination IP address
};

// tcp header struct
struct tcp_hdr {
  unsigned short tcp_scr_port;  // source TCP port
  unsigned short tcp_dest_port; // destination TCP port
  unsigned int tcp_seq;         // TCP sequence number
  unsigned int tcp_ack;         // TCP acknowledgment number
  unsigned char reserved:4;     // 4 bits of the 6 bits of reserved space
  unsigned char tcp_offset:4;   // TCP data offset for little endian host
  unsigned char tcp_flags;      // TCP flags (and the remaining 2 bits of reserved space)
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
  unsigned short tcp_window;    // TCP window size
  unsigned short tcp_checksum;  // TCP checksum
  unsigned short tcp_urgent;    // TCP urgent pointer
};

// prints program usage and then exits
void usage (char *prog_name) {
  printf("\nUsage:  %s [-i]\n\n", prog_name);
  exit(-1);
}

// prints fatal error message and then exits
void fatal (char *message) {
  char error_message[100];
  strcpy(error_message, "[!!] Fatal Error ");
  strncat(error_message, message, 82);
  perror(error_message);
  exit(-1);
}

// an error-checked malloc function
void *challoc (unsigned int size) {
  void *ptr;
  ptr = malloc(size);
  if (ptr == NULL) {
    fatal("in challoc() on memory allocation");
  }
  return ptr;
}

// converts IP address from network to host order,
// then prints as a readable string (inet_ntoa)
void print_ipv4(unsigned int addr) {
  int i, ip[4];
  char ip_string[20];
  char itoa[4];
  unsigned int ip_whole = ntohl(addr);
  ip[0] = ip_whole >> 24;
  ip[1] = (ip_whole >> 16) & 0xff;
  ip[2] = (ip_whole >> 8) & 0xff;
  ip[3] = ip_whole & 0xff;
  ip_string[0] = '\0';
  for (i=0; i<4; i++) {
    sprintf(itoa, "%d", ip[i]);
    strcat(ip_string, itoa);
    if (i != 3) strncat(ip_string, ".", 1);
  }
  printf("%s", ip_string);
}