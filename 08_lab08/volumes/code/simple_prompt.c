#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
  char input[1025];

  printf("[%s] Running process with pid = %d...\n", argv[0], getpid());

  printf("[%s] Enter a message here: ", argv[0]);
  fflush(stdout);
  fgets(input, 1024, stdin);
  printf("[%s] Received %s\n", argv[0], input);
  while(1)
    ;

  exit(0);
}
