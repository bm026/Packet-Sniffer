#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

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