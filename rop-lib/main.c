#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "./utils.c"

#define BUFF_SIZE 32
#define MSG_SIZE 64
#define ITERATIONS 2

void start_echo(){

  char input_buff[BUFF_SIZE];

  memset(input_buff, 0, BUFF_SIZE);
  get_input(input_buff, BUFF_SIZE);
  print_output(input_buff);

  return;
}


int main(){
  // Remove output buffering on stdout and stderr to fix ncat stream
  setvbuf(stdout, NULL, _IONBF, 4096);
  setvbuf(stderr, NULL, _IONBF, 4096);

  for(int i = 0; i < ITERATIONS; i++){
    start_echo();
  }

  return 0;
}
