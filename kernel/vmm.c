/*
 * virtual address mapping related functions.
 */

#include "vmm.h"
#include "riscv.h"
#include "pmm.h"
#include "util/types.h"
#include "memlayout.h"
#include "util/string.h"
#include "spike_interface/spike_utils.h"
#include "util/functions.h"
#include "process.h"

/* --- utility functions for virtual address mapping --- */
//
// establish mapping of virtual address [va, va+size] to phyiscal address [pa, pa+size]
// with the permission of "perm".
//
int map_pages(pagetable_t page_dir, uint64 va, uint64 size, uint64 pa, int perm) {
  uint64 first, last;
  pte_t *pte;

  for (first = ROUNDDOWN(va, PGSIZE), last = ROUNDDOWN(va + size - 1, PGSIZE);
      first <= last; first += PGSIZE, pa += PGSIZE) {
    if ((pte = page_walk(page_dir, first, 1)) == 0) return -1;
    if (*pte & PTE_V)
      panic("map_pages fails on mapping va (0x%lx) to pa (0x%lx)", first, pa);
    *pte = PA2PTE(pa) | perm | PTE_V;                   
  }
  return 0;
}

//
// convert permission code to permission types of PTE
//
uint64 prot_to_type(int prot, int user) {
  uint64 perm = 0;
  if (prot & PROT_READ) perm |= PTE_R | PTE_A;
  if (prot & PROT_WRITE) perm |= PTE_W | PTE_D;
  if (prot & PROT_EXEC) perm |= PTE_X | PTE_A;
  if (perm == 0) perm = PTE_R;
  if (user) perm |= PTE_U;
  return perm;
}

//
// traverse the page table (starting from page_dir) to find the corresponding pte of va.
// returns: PTE (page table entry) pointing to va.
//
pte_t *page_walk(pagetable_t page_dir, uint64 va, int alloc) {
  if (va >= MAXVA) panic("page_walk");

  // starting from the page directory
  pagetable_t pt = page_dir;

  // traverse from page directory to page table.
  // as we use risc-v sv39 paging scheme, there will be 3 layers: page dir,
  // page medium dir, and page table.
  //前两次是在页目录下找PDE
  for (int level = 2; level > 0; level--) {
    // macro "PX" gets the PTE index in page table of current level
    // "pte" points to the entry of current level
    pte_t *pte = pt + PX(level, va);

    // now, we need to know if above pte is valid (established mapping to a phyiscal page) V表示是否有对应实页
    // or not.
    if (*pte & PTE_V) {  //PTE valid
      // phisical address of pagetable of next level
      pt = (pagetable_t)PTE2PA(*pte);
    } 
    else { //PTE invalid (not exist).
      // allocate a page (to be the new pagetable), if alloc == 1
      if( alloc && ((pt = (pte_t *)alloc_page(1)) != 0) ){
        memset(pt, 0, PGSIZE);
        // writes the physical address of newly allocated page to pte, to establish the
        // page table tree.
        *pte = PA2PTE(pt) | PTE_V;
      }else //returns NULL, if alloc == 0, or no more physical page remains
        return 0;
    }
  }

  // return a PTE which contains phisical address of a page
  //这是最后一次，在页表中找PTE
  return pt + PX(0, va);
}

//
// look up a virtual page address, return the physical page address or 0 if not mapped.
//
uint64 lookup_pa(pagetable_t pagetable, uint64 va) {
  pte_t *pte;
  uint64 pa;

  if (va >= MAXVA) return 0;

  pte = page_walk(pagetable, va, 0);
  if (pte == 0 || (*pte & PTE_V) == 0 || ((*pte & PTE_R) == 0 && (*pte & PTE_W) == 0))
    return 0;
  pa = PTE2PA(*pte);

  return pa;
}

/* --- kernel page table part --- */
// _etext is defined in kernel.lds, it points to the address after text and rodata segments.
extern char _etext[];

// pointer to kernel page director
pagetable_t g_kernel_pagetable;

//
// maps virtual address [va, va+sz] to [pa, pa+sz] (for kernel).
//
void kern_vm_map(pagetable_t page_dir, uint64 va, uint64 pa, uint64 sz, int perm) {
  // map_pages is defined in kernel/vmm.c
  if (map_pages(page_dir, va, sz, pa, perm) != 0) panic("kern_vm_map");
}

//
// kern_vm_init() constructs the kernel page table. 操作系统内核的逻辑地址与物理地址在本实验中依旧是一一对应
//
void kern_vm_init(void) {
  // pagetable_t is defined in kernel/riscv.h. it's actually uint64*
  pagetable_t t_page_dir;

  // allocate a page (t_page_dir) to be the page directory for kernel. alloc_page is defined in kernel/pmm.c
  t_page_dir = (pagetable_t)alloc_page();
  // memset is defined in util/string.c
  memset(t_page_dir, 0, PGSIZE);

  // map virtual address [KERN_BASE, _etext] to physical address [DRAM_BASE, DRAM_BASE+(_etext - KERN_BASE)],
  // to maintain (direct) text section kernel address mapping.
  //映射代码段
  kern_vm_map(t_page_dir, KERN_BASE, DRAM_BASE, (uint64)_etext - KERN_BASE,
         prot_to_type(PROT_READ | PROT_EXEC, 0));

  sprint("KERN_BASE 0x%lx\n", lookup_pa(t_page_dir, KERN_BASE));

  // also (direct) map remaining address space, to make them accessable from kernel.
  // this is important when kernel needs to access the memory content of user's app
  // without copying pages between kernel and user spaces.
  //映射数据段的起始到PHYS_TOP到它对应的物理地址空间
  kern_vm_map(t_page_dir, (uint64)_etext, (uint64)_etext, PHYS_TOP - (uint64)_etext,
         prot_to_type(PROT_READ | PROT_WRITE, 0));

  sprint("physical address of _etext is: 0x%lx\n", lookup_pa(t_page_dir, (uint64)_etext));

  //记录根目录页
  g_kernel_pagetable = t_page_dir;
}

/* --- user page table part --- */
//
// convert and return the corresponding physical address of a virtual address (va) of
// application.
//
void *user_va_to_pa(pagetable_t page_dir, void *va) {
  // TODO (lab2_1): implement user_va_to_pa to convert a given user virtual address "va"
  // to its corresponding physical address, i.e., "pa". To do it, we need to walk
  // through the page table, starting from its directory "page_dir", to locate the PTE
  // that maps "va". If found, returns the "pa" by using:
  // pa = PYHS_ADDR(PTE) + (va & (1<<PGSHIFT -1))
  // Here, PYHS_ADDR() means retrieving the starting address (4KB aligned), and
  // (va & (1<<PGSHIFT -1)) means computing the offset of "va" inside its page.
  // Also, it is possible that "va" is not mapped at all. in such case, we can find
  // invalid PTE, and should return NULL.
  // panic( "You have to implement user_va_to_pa (convert user va to pa) to print messages in lab2_1.\n" );

  uint64 pa;
  uint64 ppage_start = lookup_pa(page_dir,(uint64)va);
  if(ppage_start == 0) return NULL;
  pa = ppage_start + ((uint64)va & ((1<<PGSHIFT) - 1));  
  // pa = lookup_pa(page_dir,(uint64)va)+((uint64)va & ((1<<PGSHIFT) -1));
  return (void*)pa;

}

//
// maps virtual address [va, va+sz] to [pa, pa+sz] (for user application).
//
void user_vm_map(pagetable_t page_dir, uint64 va, uint64 size, uint64 pa, int perm) {
  if (map_pages(page_dir, va, size, pa, perm) != 0) {
    panic("fail to user_vm_map .\n");
  }
}

//
// unmap virtual address [va, va+size] from the user app.
// reclaim the physical pages if free!=0
//
void user_vm_unmap(pagetable_t page_dir, uint64 va, uint64 size, int free) {
  // TODO (lab2_2): implement user_vm_unmap to disable the mapping of the virtual pages
  // in [va, va+size], and free the corresponding physical pages used by the virtual
  // addresses when if 'free' (the last parameter) is not zero.
  // basic idea here is to first locate the PTEs of the virtual pages, and then reclaim
  // (use free_page() defined in pmm.c) the physical pages. lastly, invalidate the PTEs.
  // as naive_free reclaims only one page at a time, you only need to consider one page
  // to make user/app_naive_malloc to behave correctly.
  // panic( "You have to implement user_vm_unmap to free pages using naive_free in lab2_2.\n" );
  if(free!=0)
  {
    pte_t *pte = page_walk(page_dir,va,0);
    // free_page((void*)lookup_pa(page_dir,(uint64)va));
    free_page((void*)PTE2PA(*pte));
    //修改PTE标识符
    *pte &= (~PTE_V);
  }

}

bool first_malloc=TRUE;
struct MCB* head_MCB=NULL;
//这里MCB控制块的位置有两种选择，1.集中放置 2.放在相应块内 我们采用第二种
void init_MCB_pool(){
  //初始化MCB_POOL 分配一个页面
  void* pa = alloc_page();
  uint64 va = g_ufree_page;
  user_vm_map(current->pagetable,va,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));

  head_MCB = (struct MCB*)pa;
  head_MCB->free=1;
  head_MCB->next=NULL;
  head_MCB->size=PGSIZE-sizeof(MCB);
  head_MCB->va_start=va+sizeof(MCB);
  head_MCB->pa_start=(uint64)pa+sizeof(MCB);

  //g_ufree_page表示空闲块起点
  g_ufree_page += PGSIZE;
}

uint64 better_alloc(uint64 n){

  if(first_malloc)
  {
    init_MCB_pool();
    first_malloc = FALSE;
  }
  struct MCB* cur = head_MCB;

  if(n<PGSIZE){
  while(cur!=NULL)
  {
    //先使用最简单的首次适应 符合条件  原区分裂 增加一个mcb来记录
    if(cur->free==1&&cur->size>=n+sizeof(MCB))
    {
      cur->free=0;
      //这里是一波对齐？？？
      struct MCB* split_MCB = (struct MCB*)(((uint64)(cur->pa_start + n + sizeof(MCB)) + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
      split_MCB->va_start = (cur->va_start + n + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
      split_MCB->pa_start = (cur->pa_start + n + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);

      split_MCB->free=1;
      split_MCB->size = cur->size - n - sizeof(MCB);
      // sprint("还剩下%d空间\n",split_MCB->size);
      cur->size = n;
      split_MCB->next=cur->next;
      cur->next=split_MCB;
      //这里有个小bug 可能刚好消耗完，这个块就没了。  好像也没事
      return cur->va_start;
    }
    //发现没有满足条件的，那么分配一个新的page
    if(cur->next==NULL) break;
    else cur = cur->next;
  }

  //分配足够多的page 起始是g_ufree_page
  void* pa;
  uint64 start = g_ufree_page;
  
  //这里我们先简单点，假设只多分配一个page即可 后续需修改为可按需分配多page
  pa = alloc_page();
  user_vm_map(current->pagetable,g_ufree_page,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));
  g_ufree_page+=PGSIZE;

  struct MCB* new_MCB = (struct MCB*)pa;
  new_MCB->free=0;
  new_MCB->next=NULL;
  new_MCB->size=n;
  new_MCB->va_start=start+sizeof(MCB);
  new_MCB->pa_start=(uint64)pa+sizeof(MCB);

    
  cur->next=new_MCB; 

  struct MCB* split_MCB = (struct MCB*)(((uint64)(new_MCB->pa_start + n + sizeof(MCB)) + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
  split_MCB->va_start = (new_MCB->va_start + n + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
  split_MCB->pa_start = (new_MCB->pa_start + n + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
  split_MCB->size=PGSIZE-2*sizeof(MCB)-n;
  split_MCB->next = new_MCB->next;
  new_MCB->next = split_MCB;


  return new_MCB->va_start;
  }

  //处理跨页面的 先简单点 跨两个页面
  //找最后一个块
  int page_cnt = n/PGSIZE;
  int remain = n - page_cnt*PGSIZE;
  uint64 ret_res = 0;
  //处理跨页面的 先简单点 跨两个页面
  //找最后一个块
  while(cur->next!=NULL) cur=cur->next;
  if(cur->free==1&&cur->size>remain)   //如果最后一个页可以适配余量 
  {
    // sprint("22222");
    ret_res = cur->va_start;
    cur->free=0;
    n-=cur->size;

    while(n>0)
    {
      void * pa=alloc_page();
      uint64 start = g_ufree_page;
      user_vm_map(current->pagetable,g_ufree_page,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));
      g_ufree_page+=PGSIZE;

      if(n>PGSIZE)
      {
        struct MCB* new_MCB = (struct MCB*)pa;
        new_MCB->free=0;
        new_MCB->next=NULL;
        new_MCB->size=PGSIZE-sizeof(MCB);
        new_MCB->va_start=start+sizeof(MCB);
        new_MCB->pa_start=(uint64)pa+sizeof(MCB);
        n-=new_MCB->size;
        
        cur->next=new_MCB;
        cur = new_MCB;
      }
      else  //可以分割
      {
        // sprint("333");
        struct MCB* new_MCB = (struct MCB*)pa;
        new_MCB->free=0;
        new_MCB->next=NULL;
        new_MCB->size=n;
        new_MCB->va_start=start+sizeof(MCB);
        new_MCB->pa_start=(uint64)pa+sizeof(MCB);
        
        struct MCB* split_new_MCB = (struct MCB*)(((uint64)(new_MCB->pa_start + n + sizeof(MCB)) + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
        split_new_MCB->va_start = (new_MCB->va_start + n + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
        split_new_MCB->pa_start = (new_MCB->pa_start + n + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
        split_new_MCB->free=1;
        split_new_MCB->size=PGSIZE-2*sizeof(MCB)-n;
        split_new_MCB->next=new_MCB->next;
        new_MCB->next=split_new_MCB;
        break;
      }
    }

    return ret_res;
  }
  else //不能分配余量 直接重开一个新的 最后一个放remain
  {
    void *pa;
    uint64 start;
    for(int i=0;i<page_cnt;i++)
    {
      if(i==0) ret_res = g_ufree_page;
      pa = alloc_page();
      start = g_ufree_page;
      user_vm_map(current->pagetable,g_ufree_page,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));
      g_ufree_page+=PGSIZE;

      struct MCB* new_MCB = (struct MCB*)pa;
      new_MCB->free=0;
      new_MCB->next=NULL;
      new_MCB->size=PGSIZE-sizeof(MCB);
      new_MCB->va_start=start+sizeof(MCB);
      new_MCB->pa_start=(uint64)pa+sizeof(MCB);

      cur->next = new_MCB;
      cur = new_MCB;
    }

    pa = alloc_page();
    start = g_ufree_page;
    user_vm_map(current->pagetable,g_ufree_page,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));
    g_ufree_page+=PGSIZE;
   
    struct MCB* new_MCB = (struct MCB*)pa;
    new_MCB->free=0;
    new_MCB->next=NULL;
    new_MCB->size=remain;
    new_MCB->va_start=start+sizeof(MCB);
    new_MCB->pa_start=(uint64)pa+sizeof(MCB);
    
    cur->next=new_MCB;

    struct MCB* split_new_MCB = (struct MCB*)(((uint64)(new_MCB->pa_start + remain + sizeof(MCB)) + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
    split_new_MCB->va_start = (new_MCB->va_start + remain + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
    split_new_MCB->pa_start = (new_MCB->pa_start + remain + sizeof(MCB) + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
    split_new_MCB->free=1;
    split_new_MCB->size=PGSIZE-2*sizeof(MCB)-remain;
    split_new_MCB->next=new_MCB->next;
    new_MCB->next=split_new_MCB;
    return ret_res;
  }
}



// void better_free(uint64 va){
//   struct MCB* cur = head_MCB;
//   while(cur!=NULL)
//   {
//     if(cur->va_start==va)
//     {
//       cur->free=1;

//       //当整个page都空了的时候，需要释放该page
//       // if(cur->va_start==)
//       break;
//     }
//   }
// }
void better_free(uint64 va){
  struct MCB* cur = head_MCB;
  if(cur==NULL) panic("cannot free");
  struct MCB* cur_nxt = head_MCB->next;
  //处理只有一个mcb的情况
  if(cur_nxt==NULL)
  {
    if(cur->va_start==va) cur->free=1;
    return ;
  }
  
  //正常情况
  while(cur_nxt!=NULL)
  {
    //如果是第一个匹配上了
    if(cur->va_start==va)
    {
      cur->free=1;
      //合并后方
      if(cur_nxt->free==1)
      {
        cur->next=cur_nxt->next;
        cur->size+=sizeof(MCB)+cur_nxt->size;
        return ;
      }
    }
    if(cur_nxt->va_start==va)
    {
      cur_nxt->free=1;

      //合并后方
      if(cur_nxt->next!=NULL && cur_nxt->next->free==1)
      {
        cur_nxt->size=cur_nxt->size+sizeof(MCB)+cur_nxt->next->size;
        cur_nxt->next=cur_nxt->next->next;
      }
      //合并前方
      if(cur->free==1)
      {
        cur->next=cur_nxt->next;
        cur->size+=sizeof(MCB)+cur_nxt->size;
      }
      //当整个page都空了的时候，需要释放该page
      if((cur->va_start-sizeof(MCB)-USER_FREE_ADDRESS_START)%4096==0 &&  cur->next->va_start-cur->va_start > 4096) 
      {
        user_vm_unmap((pagetable_t)current->pagetable,cur->va_start-sizeof(MCB),PGSIZE,1);
        current->user_heap.free_pages_address[current->user_heap.free_pages_count++] = cur->next->va_start-sizeof(MCB);
      }
      break;
    }
    cur = cur->next;
    cur_nxt = cur_nxt->next;
  }
}