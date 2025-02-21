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

elf_symbol symbols[64];
char sym_names[64][32];
int sym_count;


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
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1)|PTE_RSW1);

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



// leb128 (little-endian base 128) is a variable-length
// compression algoritm in DWARF
void read_uleb128(uint64 *out, char **off) {
  uint64 value = 0; int shift = 0; uint8 b;
  for (;;) {
      b = *(uint8 *)(*off); (*off)++;
      value |= ((uint64)b & 0x7F) << shift;
      shift += 7;
      if ((b & 0x80) == 0) break;
  }
  if (out) *out = value;
}
void read_sleb128(int64 *out, char **off) {
  int64 value = 0; int shift = 0; uint8 b;
  for (;;) {
      b = *(uint8 *)(*off); (*off)++;
      value |= ((uint64_t)b & 0x7F) << shift;
      shift += 7;
      if ((b & 0x80) == 0) break;
  }
  if (shift < 64 && (b & 0x40)) value |= -(1 << shift);
  if (out) *out = value;
}
// Since reading below types through pointer cast requires aligned address,
// so we can only read them byte by byte
void read_uint64(uint64 *out, char **off) {
  *out = 0;
  for (int i = 0; i < 8; i++) {
      *out |= (uint64)(**off) << (i << 3); (*off)++;
  }
}
void read_uint32(uint32 *out, char **off) {
  *out = 0;
  for (int i = 0; i < 4; i++) {
      *out |= (uint32)(**off) << (i << 3); (*off)++;
  }
}
void read_uint16(uint16 *out, char **off) {
  *out = 0;
  for (int i = 0; i < 2; i++) {
      *out |= (uint16)(**off) << (i << 3); (*off)++;
  }
}

/*
* analyzis the data in the debug_line section
*
* the function needs 3 parameters: elf context, data in the debug_line section
* and length of debug_line section
*
* make 3 arrays:
* "process->dir" stores all directory paths of code files
* "process->file" stores all code file names of code files and their directory path index of array "dir"
* "process->line" stores all relationships map instruction addresses to code line numbers
* and their code file name index of array "file"
*/
void make_addr_line(elf_ctx *ctx, char *debug_line, uint64 length) {
  sprint("111 长度%d",length);
  //我怀疑是下面这里地址有问题 至于为什么有问题
  process *p = ((elf_info *)ctx->info)->p;
  p->debugline = debug_line;
  // directory name char pointer array
  p->dir = (char **)((((uint64)debug_line + length + 7) >> 3) << 3); int dir_ind = 0, dir_base;
  // memset(p->dir, 0, 64 * sizeof(char *));
  // file name char pointer array
  p->file = (code_file *)(p->dir + 64); int file_ind = 0, file_base;
  // memset(p->file, 0, 64 * sizeof(code_file));
  // table array
  p->line = (addr_line *)(p->file + 64); p->line_ind = 0;
  // memset(p->line, 0, 64 * sizeof(addr_line));

  char *off = debug_line;

  while (off < debug_line + length) { // iterate each compilation unit(CU)
    
      sprint("yep");
      debug_header *dh = (debug_header *)off; off += sizeof(debug_header);
      dir_base = dir_ind; file_base = file_ind;
      // get directory name char pointer in this CU
      while (*off != 0) {
          p->dir[dir_ind++] = off; while (*off != 0) off++; off++;
      }
      
      // sprint("%s\n",p->dir[dir_ind-1]);

      off++;
      // get file name char pointer in this CU
      while (*off != 0) {
          p->file[file_ind].file = off; while (*off != 0) off++; off++;
          uint64 dir; read_uleb128(&dir, &off);
          p->file[file_ind++].dir = dir - 1 + dir_base;
          read_uleb128(NULL, &off); read_uleb128(NULL, &off);
          
          // sprint("本次读取的文件名和所属文件夹序号:%s,%d\n",p->file[file_ind-1].file,p->file[file_ind-1].dir);
      }
      // 这里显示文件的初始行号为1
      off++; addr_line regs; regs.addr = 0; regs.file = 1; regs.line = 1;
      // simulate the state machine op code
      for (;;) {
          uint8 op = *(off++);
          switch (op) {
              case 0: // Extended Opcodes
                  read_uleb128(NULL, &off); op = *(off++);
                  switch (op) {
                      case 1: // DW_LNE_end_sequence
                          if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                          p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                          p->line_ind++; goto endop;
                      case 2: // DW_LNE_set_address
                          read_uint64(&regs.addr, &off); break;
                      // ignore DW_LNE_define_file
                      case 4: // DW_LNE_set_discriminator
                          read_uleb128(NULL, &off); break;
                  }
                  break;
              case 1: // DW_LNS_copy
                  if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                  p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                  p->line_ind++; break;
              case 2: { // DW_LNS_advance_pc
                          uint64 delta; read_uleb128(&delta, &off);
                          regs.addr += delta * dh->min_instruction_length;
                          break;
                      }
              case 3: { // DW_LNS_advance_line
                          int64 delta; read_sleb128(&delta, &off);
                          regs.line += delta; break; } case 4: // DW_LNS_set_file
                      read_uleb128(&regs.file, &off); break;
              case 5: // DW_LNS_set_column
                      read_uleb128(NULL, &off); break;
              case 6: // DW_LNS_negate_stmt
              case 7: // DW_LNS_set_basic_block
                      break;
              case 8: { // DW_LNS_const_add_pc
                          int adjust = 255 - dh->opcode_base;
                          int delta = (adjust / dh->line_range) * dh->min_instruction_length;
                          regs.addr += delta; break;
                      }
              case 9: { // DW_LNS_fixed_advanced_pc
                          uint16 delta; read_uint16(&delta, &off);
                          regs.addr += delta;
                          break;
                      }
                      // ignore 10, 11 and 12
              default: { // Special Opcodes
                           int adjust = op - dh->opcode_base;
                           int addr_delta = (adjust / dh->line_range) * dh->min_instruction_length;
                           int line_delta = dh->line_base + (adjust % dh->line_range);
                           regs.addr += addr_delta;
                           regs.line += line_delta;
                           if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                           p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                           p->line_ind++; break;
                       }
          }
      }
endop:;
  }
  sprint("222");
  for (int i = 0; i < p->line_ind; i++)
      sprint("%p %d %d\n", p->line[i].addr, p->line[i].line, p->line[i].file);
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
    // sprint("11");
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
    
    // actual loading
    if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;

    // record the vm region in proc->mapped_info. added @lab3_1
    int j;
    int flag=0; // 检测是否增加total_mapped_region
    for( j=0; j<PGSIZE/sizeof(mapped_region); j++ ) //seek the last mapped region
      if( (process*)(((elf_info*)(ctx->info))->p)->mapped_info[j].va == 0x0 ) break;


    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = CODE_SEGMENT;
      if(((process*)(((elf_info*)(ctx->info))->p))->mapped_info[CODE_SEGMENT].npages==0) flag=1;
      sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = DATA_SEGMENT;
      if(((process*)(((elf_info*)(ctx->info))->p))->mapped_info[DATA_SEGMENT].npages==0) flag=1;
      sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
    }else
      panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );

    //这两行代码原来在上面 换个位置 用npages来判断
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].va = ph_addr.vaddr;
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].npages = 1;
    
    //这个地方需要再斟酌一下 stack 
    if(flag) ((process*)(((elf_info*)(ctx->info))->p))->total_mapped_region ++;
    flag=0;
  }

  return EL_OK;
}


static char debug_line_content[100000];
elf_status elf_load_debug_line_content(elf_ctx * ctx){

    ((elf_info *) ctx->info)->p->debugline = NULL;
    elf_sect_header shstsh;

    elf_fpread(ctx, (void*)&shstsh, sizeof(shstsh), ctx->ehdr.shoff+ctx->ehdr.shstrndx*ctx->ehdr.shentsize);

    char shstsh_content[shstsh.size];

    elf_fpread(ctx,&shstsh_content,shstsh.size,shstsh.offset);

    // for(int i=0;i<shstsh.size;i++)
    //   sprint("%c",shstsh_content[i]);

    //这个地方之前没问题
    elf_sect_header tmp;
    int i=0;
    for(;i<=ctx->ehdr.shnum;i++)
    {
        elf_fpread(ctx,(void*)&tmp,ctx->ehdr.shentsize,ctx->ehdr.shoff+i*ctx->ehdr.shentsize);
        char * section_name = &shstsh_content[tmp.name];
        // sprint("%s ",section_name);
        if(strcmp(section_name,".debug_line") == 0)
        {
            //到这也没毛病 加载的大小什么的都对的上
            // sprint("%s %d\n",section_name,tmp.size);
            if(elf_fpread(ctx,(void*)&debug_line_content,tmp.size,tmp.offset)!=tmp.size) return EL_EIO;
            make_addr_line(ctx,(char*)debug_line_content,tmp.size);
            // sprint("第几个%d",i);
            break;
        }
    }

    sprint("ok");
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
  // sprint("在这%s里",filename);
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


  load_func_name(&elfloader);
   // 在这里加载debug_line的信息 以为elf_load只加载运行相关的section
  // if (elf_load_debug_line_content(&elfloader) != EL_OK) panic("Fail on loading elf_debug_line.\n");
  
  // entry (virtual, also physical in lab1_x) address
  //记录程序的entry points
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the vfs file
  vfs_close( info.f );

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}


void exec_process_helper(process* p){
  // sprint("释放堆前,%d\n",p->mapped_info[HEAP_SEGMENT].npages);
  // 释放掉之前stack对应的页
  // user_vm_unmap(p->pagetable,p->mapped_info[STACK_SEGMENT].va,PGSIZE,1);

  // //尝试释放一下堆的空间  
  //发现释放失败 为啥嘞 因为command保存在栈里！你释放了不就没了 后面导入elf直接爆炸
  // int free_block_filter[MAX_HEAP_PAGES];
  // memset(free_block_filter, 0, MAX_HEAP_PAGES);
  // uint64 heap_bottom = p->user_heap.heap_bottom;
  // for (int i = 0; i < p->user_heap.free_pages_count; i++) {
  //   int index = (p->user_heap.free_pages_address[i] - heap_bottom) / PGSIZE;
  //   free_block_filter[index] = 1;
  // }

  // for(int64 heap_block = current->user_heap.heap_bottom;
  //   heap_block < current->user_heap.heap_top; heap_block += PGSIZE){
  //     if(!free_block_filter[(heap_block - heap_bottom) / PGSIZE])
  //       user_vm_unmap(p->pagetable,heap_block,PGSIZE,1);
  // }
  // sprint("释放堆后,%d\n",p->mapped_info[HEAP_SEGMENT].npages);
 
  //开始集成COW  Heap段集成完毕  后续集成data  开始集成data cow finish
 
  //开始尝试能不能不清零pagetable 处理一下map_pages  试验成功 这里我们就不重置堆了 带着父进程的堆走下去  那CODE_SEGMENT呢

  //pagetale清零 把fork时映射的东西去掉 现在主要是CODE_SEGMENT 不清除的话 不能二次映射了
  // memset((void *)p->pagetable, 0, PGSIZE);   

  // memset(p->trapframe, 0, sizeof(trapframe)); //trapframe清零

  //stack重新分配页
  // uint64 user_stack = (uint64)alloc_page();  
  p->trapframe->regs.sp = USER_STACK_TOP;  //重置栈顶

  // sprint("1");
  // user_vm_map((pagetable_t)p->pagetable, USER_STACK_TOP - PGSIZE, PGSIZE,
  //   user_stack, prot_to_type(PROT_WRITE | PROT_READ, 1));
  p->mapped_info[STACK_SEGMENT].va = USER_STACK_TOP - PGSIZE;
  p->mapped_info[STACK_SEGMENT].npages = 1;

  // map trapframe in user space (direct mapping as in kernel space).
  // user_vm_map((pagetable_t)p->pagetable, (uint64)p->trapframe, PGSIZE,
  //   (uint64)p->trapframe, prot_to_type(PROT_WRITE | PROT_READ, 0));

  // map S-mode trap vector section in user space (direct mapping as in kernel space)
  // we assume that the size of usertrap.S is smaller than a page.
  // user_vm_map((pagetable_t)p->pagetable, (uint64)trap_sec_start, PGSIZE,
  //   (uint64)trap_sec_start, prot_to_type(PROT_READ | PROT_EXEC, 0));


  sprint("in alloc_proc. user frame 0x%lx, user stack 0x%lx, user kstack 0x%lx \n",
    p->trapframe, p->trapframe->regs.sp, p->kstack);

  
  // map user heap in userspace
  //fork的时候分配的物理页现在不好回收 因为也没有索引确定哪些有效之类的 后续使用COW进行处理
  // sprint("此时子进程的heap有:%d\n",p->mapped_info[HEAP_SEGMENT].npages );
  // p->mapped_info[HEAP_SEGMENT].npages = 0;  // no pages are mapped to heap yet.
  // p->mapped_info[HEAP_SEGMENT].va = USER_FREE_ADDRESS_START; 
  // p->user_heap.heap_top = USER_FREE_ADDRESS_START;
  // p->user_heap.heap_bottom = USER_FREE_ADDRESS_START;
  // p->user_heap.free_pages_count = 0;
  
  // sprint("hhaha");
}



//在这个实验中，直接更改主程序的加载方式，全部从vfs中加载
//注意 在RISC-V中，main函数的参数argv保存在a1寄存器中
//这里的command para都是物理地址
int do_exec(char* command, char* para, process* p){
  //我们先清空一下process
  //elf中会导入code_segment和data_segment 我们负责重新规划 user_stack user_kernel_stack trapframe trapsec_start
  //这里模仿allc_process
  // sprint("没加载elf前进程有多少个segment:%d\n",p->total_mapped_region);
  exec_process_helper(p);

  // exec_helper(p);

  load_bincode_from_host_elf(p,command);

  // sprint("现在新的进程有多少个segment:%d\n",p->total_mapped_region);

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

void load_func_name(elf_ctx* ctx){
  memset(symbols,0,sizeof(symbols));
  memset(sym_names,0,sizeof(sym_names));
  sym_count = 0;

  // 先找到这个section header 字符串表，并把其中所有section的名字读出来
  elf_sect_header sh_str;
  elf_fpread(ctx,(void*)&sh_str,sizeof(sh_str),ctx->ehdr.shoff + ctx->ehdr.shstrndx * sizeof(elf_sect_header));
  char section_name[sh_str.size];
  // sprint("%d\n",sh_str.sh_size);
  elf_fpread(ctx,section_name,sh_str.size,sh_str.offset);
//    for(int i = 0;i < sh_str.sh_size;i++)
//        sprint("%c",section_name[i]);
//    sprint("\n");

  //找到.symtab和.strtab的header
  elf_sect_header sh_symtab;
  elf_sect_header sh_strtab;
  for(uint16 i = 0;i < ctx->ehdr.shnum;i++){
      uint64 shoff = ctx->ehdr.shoff + i * sizeof(elf_sect_header);
      elf_sect_header sh_tmp;
      elf_fpread(ctx,&sh_tmp,sizeof(sh_tmp),shoff);
      if(strcmp(section_name + sh_tmp.name,".symtab") == 0){
          sh_symtab = sh_tmp;
      }else if(strcmp(section_name + sh_tmp.name,".strtab") == 0){
          sh_strtab = sh_tmp;
      }
  }

  //读出symtab中所有函数的symbol和name，并记录数量
  uint64 symnum = sh_symtab.size / sizeof(elf_symbol);
  int i;
  int count = 0;
  elf_symbol symbol_tmp;
  for(i = 0;i < symnum;i++){
      elf_fpread(ctx,&symbol_tmp,sizeof(symbol_tmp),sh_symtab.offset + i * sizeof(elf_symbol));
      if(symbol_tmp.st_info == 18){
          elf_fpread(ctx,sym_names[count],sizeof(sym_names[count]),sh_strtab.offset + symbol_tmp.st_name);
          symbols[count] = symbol_tmp;
           sprint("%s\n",sym_names[count]);
          count++;
      }
  }
  sym_count = count;
}