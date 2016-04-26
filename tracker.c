#include "h_tracker.h"

int main (int argc, char *argv[]) {

  // if incorrect command line arguments, show usage and exit
  if (argc > 2 || (argc == 2 && strcmp(argv[1], "-i") != 0)) {
    usage(argv[0]);
  }

  return 0;
}