#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
  printf("[%s] Running process with pid = %d...\n", argv[0], getpid());

  printf("My file descriptors are the following:\n");
  printf("\t stdin:  %d\n", STDIN_FILENO);
  printf("\t stdout: %d\n", STDOUT_FILENO);
  printf("\t stderr: %d\n", STDERR_FILENO);
  fflush(stdout);

  while(1)
    ;

  exit(0);
}
