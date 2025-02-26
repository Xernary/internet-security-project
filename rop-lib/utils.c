#include <string.h>
#include <stdio.h>
#include <unistd.h>

// Vulnerable utils library

void get_input(char* buff, int size){
  memset(buff, 0, size);
  printf("%s", "Insert stuff here\n");
  read(0, buff, 1024); // BOF
}

void print_output(char* buff){
  printf("Hello, ");
  printf(buff); // Leak
}



