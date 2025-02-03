#include "user_lib.h"
#include "util/string.h"
#include "util/types.h"


int main(int argc, char *argv[]) {
  char *new_dir = argv[0];
  //他这个现在直接是物理地址 是不是要换成虚拟地址
  // printu("\n new_dir:%llx",(uint64)new_dir);

  printu("\n======== mkdir command ========\n");
  mkdir_u(new_dir);
  printu("mkdir: %s\n", new_dir);

  exit(0);
  return 0;
}
