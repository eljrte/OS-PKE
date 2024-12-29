/*
 * The application of lab3_2.
 * parent and child processes intermittently give up their processors.
 */

#include "user/user_lib.h"
#include "util/types.h"

int main(void) {
  uint64 pid = fork();    //fork在子进程返回0 在父进程返回子进程的 PID
  uint64 rounds = 0xffff;
  if (pid == 0) {
    printu("Child: Hello world! \n");
    for (uint64 i = 0; i < rounds; ++i) {
      if (i % 10000 == 0) {
        printu("Child running %ld \n", i);
        yield();    //放弃CPU进入就绪状态
      }
    }
  } else {
    printu("Parent: Hello world! \n");
    for (uint64 i = 0; i < rounds; ++i) {
      if (i % 10000 == 0) {
        printu("Parent running %ld \n", i);
        yield();
      }
    }
  }

  exit(0);
  return 0;
}
