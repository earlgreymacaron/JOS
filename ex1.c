//
// Simple inline assembly example
//
// For JOS lab 1 exercise 1
//

#include <stdio.h>

int
main(int argc, char **argv)
{
  int x = 1;
  printf("Hello x = %d\n", x);

  // Inline assembly to increment x
  // note for self-study:
  //    %eax is used as both input and output.
  //    x is read and updated %eax
  //    "0" sepecifies the same constraint as 0th output
  __asm__ ("incl %0" : "=a" (x) : "0"(x));

  printf("Hello x = %d after increment\n", x);

  if(x == 2){
    printf("OK\n");
  }
  else{
    printf("ERROR\n");
  }
}
