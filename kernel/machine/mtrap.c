#include "kernel/riscv.h"
#include "kernel/process.h"
#include "spike_interface/spike_utils.h"
#include "string.h"

static void handle_instruction_access_fault() { panic("Instruction access fault!"); }

static void handle_load_access_fault() { panic("Load access fault!"); }

static void handle_store_access_fault() { panic("Store/AMO access fault!"); }

static void handle_illegal_instruction() { panic("Illegal instruction!"); }

static void handle_misaligned_load() { panic("Misaligned Load!"); }

static void handle_misaligned_store() { panic("Misaligned AMO!"); }

// added @lab1_3
static void handle_timer() {
  int cpuid = 0;
  // setup the timer fired at next time (TIMER_INTERVAL from now)
  *(uint64*)CLINT_MTIMECMP(cpuid) = *(uint64*)CLINT_MTIMECMP(cpuid) + TIMER_INTERVAL;

  // setup a soft interrupt in sip (S-mode Interrupt Pending) to be handled in S-mode
  //触发一次软件中断
  write_csr(sip, SIP_SSIP);
}


void print_error_line(uint64 error_addr){
  // sprint("%llx",error_addr);
  uint64 file_idx=0,line_idx=0,dir_idx=0;

  for(int i=0;i<current->line_ind;i++)
  {
    if(current->line[i].addr == error_addr)
    {
      file_idx = current->line[i].file;
      line_idx = current->line[i].line;
      break;
    }
  }

  dir_idx = current->file[file_idx].dir;

  //如果是用户源程序发生的错误，路径为相对路径，如果是调用的标准库内发生的错误，路径为绝对路径。
  //经打印p->dir发现:
  // user 
  // /home/pke/riscv64-elf-gcc/lib/gcc/riscv64-unknown-elf/11.1.0/include
  // ./util
  char file_path[4096];
  strcpy(file_path,current->dir[dir_idx]);
  file_path[strlen(current->dir[dir_idx])] = '/';
  strcpy(file_path+strlen(current->dir[dir_idx])+1,current->file[file_idx].file);

  sprint("Runtime error at %s:%d\n",file_path,line_idx);


  // sprint("%s",file_path);
  
  spike_file_t *fd = spike_file_open(file_path,O_RDONLY,0);
  struct stat file;
  spike_file_stat(fd,&file);
  char buf[file.st_size];
  spike_file_read(fd,(void*)buf,file.st_size);
  // sprint("%s",file_buf);

  char *off = buf;
  uint64 file_line_id = 1;
  while(off < buf + file.st_size)
  {
    if(file_line_id == line_idx)
    {
      char tmp_buf[4096];
      int i=0;
      while(*off!='\n')
      {
        tmp_buf[i++]=*off;
        off++;
      }
      tmp_buf[i] = '\0';
      sprint("%s\n",tmp_buf);
      break;
    }
    while(*off != '\n')  off++;
    off++; file_line_id++;

  }

spike_file_close(fd);

}


//
// handle_mtrap calls a handling function according to the type of a machine mode interrupt (trap).
//
void handle_mtrap() {
  uint64 mcause = read_csr(mcause);

  uint64 mepc = read_csr(mepc);

  print_error_line(mepc);
  switch (mcause) {
    case CAUSE_MTIMER:
      handle_timer();
      break;
    case CAUSE_FETCH_ACCESS:
      handle_instruction_access_fault();
      break;
    case CAUSE_LOAD_ACCESS:
      handle_load_access_fault();
    case CAUSE_STORE_ACCESS:
      handle_store_access_fault();
      break;
    case CAUSE_ILLEGAL_INSTRUCTION:
      // TODO (lab1_2): call handle_illegal_instruction to implement illegal instruction
      // interception, and finish lab1_2.
      handle_illegal_instruction();
      // panic( "call handle_illegal_instruction to accomplish illegal instruction interception for lab1_2.\n" );

      break;
    case CAUSE_MISALIGNED_LOAD:
      handle_misaligned_load();
      break;
    case CAUSE_MISALIGNED_STORE:
      handle_misaligned_store();
      break;

    default:
      sprint("machine trap(): unexpected mscause %p\n", mcause);
      sprint("            mepc=%p mtval=%p\n", read_csr(mepc), read_csr(mtval));
      panic( "unexpected exception happened in M-mode.\n" );
      break;
  }
}
