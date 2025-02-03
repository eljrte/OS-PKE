/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "vmm.h"
#include "pmm.h"
#include "vfs.h"
#include "spike_interface/spike_utils.h"
#include "memlayout.h"


extern char trap_sec_start[];

typedef struct elf_info_t {
  struct file *f;
  process *p;
}elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading.
// this allocater is heavily modified @lab2_1, where we do NOT work in bare mode.
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  elf_info *msg = (elf_info *)ctx->info;
  // we assume that size of proram segment is smaller than a page.
  kassert(size < PGSIZE);
  void *pa = alloc_page();
  if (pa == 0) panic("uvmalloc mem alloc falied\n");

  memset((void *)pa, 0, PGSIZE);
  user_vm_map((pagetable_t)msg->p->pagetable, elf_va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1));

  return pa;
}

//
// actual file reading, using the vfs file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  vfs_lseek(msg->f, offset, SEEK_SET);
  return vfs_read(msg->f, dest, nb);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

//
// load the elf segments to memory regions.
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // actual loading
    if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;

    // record the vm region in proc->mapped_info. added @lab3_1
    int j;
    for( j=0; j<PGSIZE/sizeof(mapped_region); j++ ) //seek the last mapped region
      if( (process*)(((elf_info*)(ctx->info))->p)->mapped_info[j].va == 0x0 ) break;

    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].va = ph_addr.vaddr;
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].npages = 1;

    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = CODE_SEGMENT;
      sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = DATA_SEGMENT;
      sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
    }else
      panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );

    ((process*)(((elf_info*)(ctx->info))->p))->total_mapped_region ++;
  }

  return EL_OK;
}

//
// load the elf of user application, by using the spike file interface.
//
void load_bincode_from_host_elf(process *p, char *filename) {
  sprint("Application: %s\n", filename);

  //elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  // elf_info is defined above, used to tie the elf file and its corresponding process.
  elf_info info;

  //这里就是使用的vfs导入elf的
  info.f = vfs_open(filename, O_RDONLY);
  info.p = p;
  // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
  if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK)
    panic("fail to init elfloader.\n");

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  //记录程序的entry points
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the vfs file
  vfs_close( info.f );

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}


void exec_process_helper(process* p){
 // init proc[i]'s vm space
  p->trapframe = (trapframe *)alloc_page();  //trapframe, used to save context
  memset(p->trapframe, 0, sizeof(trapframe));

  // page directory
  p->pagetable = (pagetable_t)alloc_page();
  memset((void *)p->pagetable, 0, PGSIZE);

  p->kstack = (uint64)alloc_page() + PGSIZE;   //user kernel stack top
  uint64 user_stack = (uint64)alloc_page();       //phisical address of user stack bottom
  p->trapframe->regs.sp = USER_STACK_TOP;  //virtual address of user stack top

  // allocates a page to record memory regions (segments)
  p->mapped_info = (mapped_region*)alloc_page();
  memset( p->mapped_info, 0, PGSIZE );

  // map user stack in userspace
  user_vm_map((pagetable_t)p->pagetable, USER_STACK_TOP - PGSIZE, PGSIZE,
    user_stack, prot_to_type(PROT_WRITE | PROT_READ, 1));
  p->mapped_info[STACK_SEGMENT].va = USER_STACK_TOP - PGSIZE;
  p->mapped_info[STACK_SEGMENT].npages = 1;
  p->mapped_info[STACK_SEGMENT].seg_type = STACK_SEGMENT;

  // map trapframe in user space (direct mapping as in kernel space).
  user_vm_map((pagetable_t)p->pagetable, (uint64)p->trapframe, PGSIZE,
    (uint64)p->trapframe, prot_to_type(PROT_WRITE | PROT_READ, 0));
  p->mapped_info[CONTEXT_SEGMENT].va = (uint64)p->trapframe;
  p->mapped_info[CONTEXT_SEGMENT].npages = 1;
  p->mapped_info[CONTEXT_SEGMENT].seg_type = CONTEXT_SEGMENT;

  // map S-mode trap vector section in user space (direct mapping as in kernel space)
  // we assume that the size of usertrap.S is smaller than a page.
  user_vm_map((pagetable_t)p->pagetable, (uint64)trap_sec_start, PGSIZE,
    (uint64)trap_sec_start, prot_to_type(PROT_READ | PROT_EXEC, 0));
  p->mapped_info[SYSTEM_SEGMENT].va = (uint64)trap_sec_start;
  p->mapped_info[SYSTEM_SEGMENT].npages = 1;
  p->mapped_info[SYSTEM_SEGMENT].seg_type = SYSTEM_SEGMENT;

  sprint("in alloc_proc. user frame 0x%lx, user stack 0x%lx, user kstack 0x%lx \n",
    p->trapframe, p->trapframe->regs.sp, p->kstack);

  // initialize the process's heap manager
  p->user_heap.heap_top = USER_FREE_ADDRESS_START;
  p->user_heap.heap_bottom = USER_FREE_ADDRESS_START;
  p->user_heap.free_pages_count = 0;

  // map user heap in userspace
  p->mapped_info[HEAP_SEGMENT].va = USER_FREE_ADDRESS_START;
  p->mapped_info[HEAP_SEGMENT].npages = 0;  // no pages are mapped to heap yet.
  p->mapped_info[HEAP_SEGMENT].seg_type = HEAP_SEGMENT;

  p->total_mapped_region = 4;

  p->pfiles = init_proc_file_management();

}



//在这个实验中，直接更改主程序的加载方式，全部从vfs中加载
//注意 在RISC-V中，main函数的参数argv保存在a1寄存器中
int do_exec(char* command, char* para, process* p){
  //我们先清空一下process
  //elf中会导入code_segment和data_segment 我们负责重新规划 user_stack user_kernel_stack trapframe trapsec_start
  //这里模仿allc_process
  exec_process_helper(p);

  load_bincode_from_host_elf(p,command);

  //然后传入一下参数 我们只需要传入一个地址即可
  //该地址与我们的para关联即可
  void *pa = alloc_page();
  uint64 va = p->user_heap.heap_top;
  p->user_heap.heap_top += PGSIZE;
  p->mapped_info[HEAP_SEGMENT].npages++;
  user_vm_map((pagetable_t)p->pagetable,va,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));

  // *(uint64*)pa = (uint64)para;

  // *(char**)pa = para;

  p->trapframe->regs.a1 = (uint64)va;


  va = p->user_heap.heap_top;
  p->user_heap.heap_top += PGSIZE;
  p->mapped_info[HEAP_SEGMENT].npages++;
  user_vm_map((pagetable_t)p->pagetable,va,PGSIZE,(uint64)para,prot_to_type(PROT_WRITE | PROT_READ, 1));

  *(uint64*)pa = (uint64)va;

  // sprint("传过去的va:%llx,对应的pa:%llx,para的实际地址:%llx",va,pa,para);

  return 0;
}