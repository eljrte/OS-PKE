/*
 * The application of lab3_3.
 * parent and child processes never give up their processor during execution.
 */

#include "user/user_lib.h"
#include "util/types.h"

int main(void) {
<<<<<<< HEAD:user/app_two_long_loops.c
  uint64 pid = fork();
  uint64 rounds = 100000000;
  uint64 interval = 10000000;
  uint64 a = 0;
  if (pid == 0) {
    printu("Child: Hello world! \n");
    for (uint64 i = 0; i < rounds; ++i) {
      if (i % interval == 0) printu("Child running %ld \n", i);
=======
  uint64 pid = fork();    //fork在子进程返回0 在父进程返回子进程的 PID
  uint64 rounds = 0xffff;
  if (pid == 0) {
    printu("Child: Hello world! \n");
    for (uint64 i = 0; i < rounds; ++i) {
      if (i % 10000 == 0) {
        printu("Child running %ld \n", i);
        yield();    //放弃CPU进入就绪状态
      }
>>>>>>> lab3_2_yield:user/app_yield.c
    }
  } else {
    printu("Parent: Hello world! \n");
    for (uint64 i = 0; i < rounds; ++i) {
      if (i % interval == 0) printu("Parent running %ld \n", i);
    }
  }

  exit(0);
  return 0;
}
