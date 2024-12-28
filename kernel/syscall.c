/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "process.h"
#include "util/functions.h"
#include "elf.h"

#include "spike_interface/spike_utils.h"


extern elf_symbol symbols[64];
extern char sym_names[64][32];
extern int sym_count;

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
  sprint(buf);
  return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
  sprint("User exit with code:%d.\n", code);
  // in lab1, PKE considers only one app (one process). 
  // therefore, shutdown the system when the app calls exit()
  shutdown(code);
}

int funcion_name_printer(uint64 ret_addr) {
  //f1 f2 f3 ...函数入口地址递减
  // sprint("这里的ret_addr是:%llx",ret_addr);
  //ret_addr是f函数中间的一行代码，需要一个区间来确认
  for(int i=0;i<sym_count;i++){
    //sprint("%d %d %d\n", ret_addr, symbols[i].st_value, symbols[i].st_size);
    if(ret_addr >= symbols[i].st_value&&ret_addr < symbols[i].st_value+symbols[i].st_size){
      sprint("%s\n",sym_names[i]);
      if(strcmp(sym_names[i],"main")==0) return 0;
      return 1;
    }
  }
  return 0;
}

ssize_t sys_print_backtrace(uint64 num){
  // ra返回地址 sp栈顶指针 压栈的时候（除叶子节点外）ra在sp上面
  // 栈顶表示栈的低地址端（下方） 栈底为栈的高地址端（上方）
  //do_user_call的栈帧有32个字节，+32，获得print_backtrace的栈顶sp
  //其余f*函数的栈帧为16字节   fp + ra
  //再+8，获取print_backtrace的ra
  uint64 trace_sp_do_user_call = current -> trapframe ->regs.sp + 32;
  uint64 trace_ra = trace_sp_do_user_call + 8;

  int i=0;
  for(;i<num;i++)
  {
    if(funcion_name_printer(*(uint64*)trace_ra) == 0) return i;
      trace_ra += 16;
  }
  return i;
}
//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
  switch (a0) {
    case SYS_user_print:
      return sys_user_print((const char*)a1, a2);
    case SYS_user_exit:
      return sys_user_exit(a1);
    case SYS_print_backtrace:
      return sys_print_backtrace(a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
